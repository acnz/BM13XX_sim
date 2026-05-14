#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "soc/hwcrypto_reg.h"
#include "soc/dport_reg.h"

// Endereços físicos do módulo SHA no ESP32 padrão (não-C3) definidos no BitsyMiner
#define SHA_TEXT_BASE    0x3FF03000
#define SHA_START_REG    0x3FF03090
#define SHA_LOAD_REG     0x3FF03098
#define SHA_BUSY_REG     0x3FF0309C

#define SIM_TXD_PIN CONFIG_UART_TXD
#define SIM_RXD_PIN CONFIG_UART_RXD
#define SIM_UART_PORT CONFIG_UART_PORT_NUM
#define BUF_SIZE 1024

static const char *TAG = "BM13XX_hwSHA256";

// Mutex para evitar que os dois núcleos tentem escrever na Serial ao mesmo tempo
static SemaphoreHandle_t uart_mutex;

// Variáveis Globais do Trabalho (O Maestro atualiza, os Operários leem)
volatile uint32_t g_job_version = 0;
uint32_t g_digest[8];
uint32_t g_bake[15];
uint8_t g_dataIn[16];

// ============================================================================
// NÚCLEO SHA-256 EXTREMO (BAKING + EARLY EXIT DO NERDMINER V2)
// ============================================================================
#define GET_UINT32_BE(b, i) (((uint32_t)(b)[(i)] << 24) | ((uint32_t)(b)[(i) + 1] << 16) | ((uint32_t)(b)[(i) + 2] << 8) | ((uint32_t)(b)[(i) + 3]))

static const uint32_t K[64] = {
    0x428A2F98L, 0x71374491L, 0xB5C0FBCFL, 0xE9B5DBA5L, 0x3956C25BL, 0x59F111F1L, 0x923F82A4L, 0xAB1C5ED5L,
    0xD807AA98L, 0x12835B01L, 0x243185BEL, 0x550C7DC3L, 0x72BE5D74L, 0x80DEB1FEL, 0x9BDC06A7L, 0xC19BF174L,
    0xE49B69C1L, 0xEFBE4786L, 0x0FC19DC6L, 0x240CA1CCL, 0x2DE92C6FL, 0x4A7484AAL, 0x5CB0A9DCL, 0x76F988DAL,
    0x983E5152L, 0xA831C66DL, 0xB00327C8L, 0xBF597FC7L, 0xC6E00BF3L, 0xD5A79147L, 0x06CA6351L, 0x14292967L,
    0x27B70A85L, 0x2E1B2138L, 0x4D2C6DFCL, 0x53380D13L, 0x650A7354L, 0x766A0ABBL, 0x81C2C92EL, 0x92722C85L,
    0xA2BFE8A1L, 0xA81A664BL, 0xC24B8B70L, 0xC76C51A3L, 0xD192E819L, 0xD6990624L, 0xF40E3585L, 0x106AA070L,
    0x19A4C116L, 0x1E376C08L, 0x2748774CL, 0x34B0BCB5L, 0x391C0CB3L, 0x4ED8AA4AL, 0x5B9CCA4FL, 0x682E6FF3L,
    0x748F82EEL, 0x78A5636FL, 0x84C87814L, 0x8CC70208L, 0x90BEFFFAL, 0xA4506CEBL, 0xBEF9A3F7L, 0xC67178F2L
};

#define SHR(x, n) ((x & 0xFFFFFFFF) >> n)
#define ROTR(x, n) ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define S0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define S1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))
#define S2(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S3(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define F0(x, y, z) ((x & y) | (z & (x | y)))
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define R(t) (W[t] = S1(W[t - 2]) + W[t - 7] + S0(W[t - 15]) + W[t - 16])
#define P(a, b, c, d, e, f, g, h, x, K) { temp1 = h + S3(e) + F1(e, f, g) + K + x; temp2 = S2(a) + F0(a, b, c); d += temp1; h = temp1 + temp2; }

// Função para ligar o módulo SHA (Baseado na macro INIT_HARDWARE_SHA256 do miner.h)
void init_hardware_sha() {
    DPORT_REG_SET_BIT(DPORT_PERI_CLK_EN_REG, DPORT_PERI_EN_SHA);
    DPORT_REG_CLR_BIT(DPORT_PERI_RST_EN_REG, DPORT_PERI_EN_SHA | DPORT_PERI_EN_SECUREBOOT);
}

// Função que executa EXCLUSIVAMENTE o segundo hash no hardware
bool second_hash_hardware(uint32_t* first_hash_32bytes) {
    volatile uint32_t *sha_text = (volatile uint32_t*) SHA_TEXT_BASE;

    // 1. Espera o hardware ficar ocioso
    while (*(volatile uint32_t *)(SHA_BUSY_REG) != 0);

    // 2. Escreve os 32 bytes do primeiro hash no hardware
    for(int i = 0; i < 8; i++) {
        sha_text[i] = first_hash_32bytes[i];
    }

    // 3. O algoritmo SHA256 exige um padding no final da mensagem.
    // Como a mensagem tem exatamente 32 bytes (256 bits), o padding é previsível:
    // Um bit '1' (0x80000000), seguido de zeros, e o tamanho da mensagem (256 bits = 0x00000100) no final.
    sha_text[8] = 0x80000000;
    for(int i = 9; i < 15; i++) {
        sha_text[i] = 0;
    }
    sha_text[15] = 0x00000100; // Tamanho em bits (256)

    // 4. Inicia a operação SHA256 do ZERO (START)
    *(volatile uint32_t *)(SHA_START_REG) = 1;

    // 5. Espera o cálculo terminar
    while (*(volatile uint32_t *)(SHA_BUSY_REG) != 0);

    // 6. Manda o hardware carregar o resultado de volta para os registradores TEXT
    *(volatile uint32_t *)(SHA_LOAD_REG) = 1;
    while (*(volatile uint32_t *)(SHA_BUSY_REG) != 0);

    if ((sha_text[7] & 0xFFFFFF) == 0) {
        return true;
    }
    return false;
}

void nerd_sha256_bake(const uint32_t* digest, const uint8_t* dataIn, uint32_t* bake) {
    bake[0] = GET_UINT32_BE(dataIn, 0); bake[1] = GET_UINT32_BE(dataIn, 4); bake[2] = GET_UINT32_BE(dataIn, 8);
    bake[3] = S1(0) + 0 + S0(bake[1]) + bake[0]; bake[4] = S1(640) + 0 + S0(bake[2]) + bake[1];
    uint32_t* a = bake + 5;
    for(int i=0; i<8; i++) a[i] = digest[i];
    uint32_t temp1, temp2;
    P(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], bake[0], K[0]);
    P(a[7], a[0], a[1], a[2], a[3], a[4], a[5], a[6], bake[1], K[1]);
    P(a[6], a[7], a[0], a[1], a[2], a[3], a[4], a[5], bake[2], K[2]);
    bake[13] = a[4] + S3(a[1]) + F1(a[1], a[2], a[3]) + K[3];
    bake[14] = S2(a[5]) + F0(a[5], a[6], a[7]);
}

// Esta diretiva obriga o compilador a usar velocidade máxima (O3) nesta função!
#pragma GCC optimize ("O3")

bool nerd_sha256d_baked(const uint32_t* digest, const uint8_t* dataIn, const uint32_t* bake) {
    uint32_t W[64];
    uint32_t A[8];
    uint32_t temp1, temp2;
    
    // ============================================
    // 1º SHA-256
    // ============================================
    W[0] = bake[0]; W[1] = bake[1]; W[2] = bake[2]; 
    W[3] = GET_UINT32_BE(dataIn, 12);
    W[4] = 0x80000000;
    for(int i=5; i<15; i++) W[i] = 0;
    W[15] = 640;
    W[16] = bake[3]; W[17] = bake[4];
    
    // Expansão da mensagem
    for(int i=18; i<64; i++) {
        W[i] = S1(W[i - 2]) + W[i - 7] + S0(W[i - 15]) + W[i - 16];
    }
    
    A[0] = bake[5]; A[1] = bake[6]; A[2] = bake[7]; A[3] = bake[8];
    A[4] = bake[9]; A[5] = bake[10]; A[6] = bake[11]; A[7] = bake[12];
    
    // As 4 primeiras rodadas já vieram "Assadas" (Baked) pelo Maestro
    temp1 = bake[13] + W[3];
    temp2 = bake[14];
    A[0] += temp1;
    A[4] = temp1 + temp2;
    
    // Rodadas 4 a 7
    P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], W[4], K[4]);
    P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], W[5], K[5]);
    P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], W[6], K[6]);
    P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], W[7], K[7]);
    
    // Rodadas 8 a 63 em blocos compactos de 8 (Cabe na L1 Cache!)
    for(int i=8; i<64; i+=8) {
        P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], W[i+0], K[i+0]);
        P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], W[i+1], K[i+1]);
        P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], W[i+2], K[i+2]);
        P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], W[i+3], K[i+3]);
        P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], W[i+4], K[i+4]);
        P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], W[i+5], K[i+5]);
        P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], W[i+6], K[i+6]);
        P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], W[i+7], K[i+7]);
    }
    
    // ============================================
    // 2º SHA-256 VIA ACELERADOR DE HARDWARE
    // ============================================
    
    // 1. Preparamos o input isolando os 32 bytes do resultado do 1º Hash
    uint32_t first_hash[8];
    first_hash[0] = A[0] + digest[0];
    first_hash[1] = A[1] + digest[1];
    first_hash[2] = A[2] + digest[2];
    first_hash[3] = A[3] + digest[3];
    first_hash[4] = A[4] + digest[4];
    first_hash[5] = A[5] + digest[5];
    first_hash[6] = A[6] + digest[6];
    first_hash[7] = A[7] + digest[7];

    // 3. Deixamos o hardware fritar os dados e Checagem de Dificuldade da ASIC (16 zeros)
    // Importante: No caso de hashes raríssimos muito difíceis, a Bitmain exige
    // verificações extras. Mas para o `send_bitmain_response`, basta os 32 bits zerados.
    return second_hash_hardware(first_hash);
}

// ============================================================================
// COMUNICAÇÃO SERIAL BITMAIN E MULTIPROCESSAMENTO
// ============================================================================
uint8_t get_crc5(uint8_t *ptr, uint8_t len) {
    uint8_t crc = 0x1f;
    for (int i = 0; i < len; i++) {
        crc ^= ptr[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 0x80) crc = (crc << 1) ^ 0x05;
            else crc <<= 1;
        }
    }
    return ((crc >> 3) & 0x1f);
}

void send_bitmain_response(uint32_t nonce) {
    unsigned char buf_nonce[11] = {0xAA, 0x55, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0};
    buf_nonce[4] = (nonce >> 24) & 0xFF; buf_nonce[5] = (nonce >> 16) & 0xFF;
    buf_nonce[6] = (nonce >> 8)  & 0xFF; buf_nonce[7] = (nonce >> 0)  & 0xFF;
    buf_nonce[10] = get_crc5(buf_nonce, 10);
    
    // Mutex para evitar que o Core 0 e o Core 1 atropelem os bytes um do outro
    if (xSemaphoreTake(uart_mutex, portMAX_DELAY)) {
        uart_write_bytes(SIM_UART_PORT, buf_nonce, 11);
        xSemaphoreGive(uart_mutex);
    }
}


// OS OPERÁRIOS: Tarefas que rodam o código Extremo de mineração
static void miner_task(void *arg) {
    int core_id = (int)arg; // Recebe o número do núcleo (0 ou 1)
    
    uint32_t local_version = 0;
    uint32_t digest[8], bake[15];
    uint8_t dataIn[16];
    
    // O pulo do gato: Core 0 testa pares, Core 1 testa ímpares!
    uint32_t nonce = core_id; 
    uint32_t hashes = 0;
    uint32_t start_time = xTaskGetTickCount();

    while(1) {
        // Se o Maestro (UART) recebeu bloco novo, o Operário atualiza sua prancheta
        if (g_job_version != local_version) {
            local_version = g_job_version;
            memcpy(digest, g_digest, 32);
            memcpy(bake, g_bake, 60);
            memcpy(dataIn, g_dataIn, 16);
            nonce = core_id; // Reseta o nonce (0 ou 1)
            hashes = 0;
            start_time = xTaskGetTickCount();
        }

        // Fica aguardando o primeiro bloco da internet chegar
        if (local_version == 0) {
            vTaskDelay(100 / portTICK_PERIOD_MS);
            continue;
        }

        dataIn[12] = (nonce >> 0) & 0xFF; dataIn[13] = (nonce >> 8) & 0xFF;
        dataIn[14] = (nonce >> 16) & 0xFF; dataIn[15] = (nonce >> 24) & 0xFF;

        if (nerd_sha256d_baked(digest, dataIn, bake)) {
            ESP_LOGI(TAG, "[Core %d] Share Encontrado! Nonce: %08lx", core_id, (unsigned long)nonce);
            send_bitmain_response(nonce);
        }

        // Pula de 2 em 2 (mantendo pares ou ímpares)
        nonce += 2;
        hashes++;

        if (hashes % 2000 == 0) vTaskDelay(1); // Respiro do Watchdog

        if (hashes % 100000 == 0) {
            uint32_t diff = (xTaskGetTickCount() - start_time) * portTICK_PERIOD_MS;
            uint32_t hr = (hashes * 1000) / (diff > 0 ? diff : 1);
            ESP_LOGW(TAG, "[Core %d] Velocidade: %lu H/s", core_id, (unsigned long)hr);
        }
    }
}

// O MAESTRO: Fica ouvindo a C3 pela porta serial
static void uart_listener_task(void *arg) {
    uart_config_t uart_config = {
        .baud_rate = 115200, .data_bits = UART_DATA_8_BITS, .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1, .flow_ctrl = UART_HW_FLOWCTRL_DISABLE, .source_clk = UART_SCLK_DEFAULT,
    };
    ESP_ERROR_CHECK(uart_param_config(SIM_UART_PORT, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(SIM_UART_PORT, SIM_TXD_PIN, SIM_RXD_PIN, -1, -1));
    ESP_ERROR_CHECK(uart_driver_install(SIM_UART_PORT, BUF_SIZE * 2, BUF_SIZE * 2, 0, NULL, 0));

    uint8_t *data = (uint8_t *)malloc(BUF_SIZE);
    ESP_LOGI(TAG, "Músculo Dual-Core Iniciado. Aguardando Work...");

    while (1) {
        int len = uart_read_bytes(SIM_UART_PORT, data, 128, 20 / portTICK_PERIOD_MS);
        if (len > 0) {
            if (strstr((char*)data, "PING") != NULL) { uart_write_bytes(SIM_UART_PORT, "PONG", 4); continue; }

            if (len >= 6 && data[2] == 0x21) {
                ESP_LOGE(TAG, "=> SEND_WORK Recebido! Assando e acionando Operários!");
                uart_flush(SIM_UART_PORT);

                // Variáveis temporárias para não atrapalhar os operários enquanto calcula
                uint32_t t_digest[8], t_bake[15]; uint8_t t_dataIn[16] = {0};
                for(int i=0; i<8; i++) t_digest[i] = GET_UINT32_BE((&data[4]), i*4);
                memcpy(t_dataIn, &data[36], 12); 
                nerd_sha256_bake(t_digest, t_dataIn, t_bake);
                
                // Atualiza as variáveis globais (Prancheta de Trabalho)
                memcpy(g_digest, t_digest, 32);
                memcpy(g_bake, t_bake, 60);
                memcpy(g_dataIn, t_dataIn, 16);
                
                // O GATILHO: Quando muda a versão, os dois núcleos resetam e recomeçam
                g_job_version++; 
            }
            // Negociação de Baudrate padrão da Bitmain
            else if (data[2] == 0x51 && data[5] == 0x28) {
                uart_wait_tx_done(SIM_UART_PORT, 1000 / portTICK_PERIOD_MS);
                uart_set_baudrate(SIM_UART_PORT, 1000000);
            }
        }
    }
}

void app_main(void) {
    uart_mutex = xSemaphoreCreateMutex();

    // Cria o Maestro (Fica ouvindo a UART no Core 0, consome quase nada)
    xTaskCreatePinnedToCore(uart_listener_task, "uart_task", 8192, NULL, 5, NULL, 1);
    init_hardware_sha();
    // Cria os DOIS OPERÁRIOS (O Músculo Real), pregando um em cada núcleo
    xTaskCreatePinnedToCore(miner_task, "miner_core0", 8192, (void*)0, 10, NULL, 0);
    xTaskCreatePinnedToCore(miner_task, "miner_core1", 8192, (void*)1, 10, NULL, 1);
}