#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_log.h"

#define SIM_TXD_PIN CONFIG_UART_TXD
#define SIM_RXD_PIN CONFIG_UART_RXD
#define SIM_UART_PORT CONFIG_UART_PORT_NUM
#define BUF_SIZE 1024

static const char *TAG = "BM13XX_sim_single";

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

// A Função que Assa (Bake) os dados estáticos antes do loop
void nerd_sha256_bake(const uint32_t* digest, const uint8_t* dataIn, uint32_t* bake) {
    bake[0] = GET_UINT32_BE(dataIn, 0);
    bake[1] = GET_UINT32_BE(dataIn, 4);
    bake[2] = GET_UINT32_BE(dataIn, 8);
    bake[3] = S1(0) + 0 + S0(bake[1]) + bake[0];
    bake[4] = S1(640) + 0 + S0(bake[2]) + bake[1];

    uint32_t* a = bake + 5;
    for(int i=0; i<8; i++) a[i] = digest[i];

    uint32_t temp1, temp2;
    P(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], bake[0], K[0]);
    P(a[7], a[0], a[1], a[2], a[3], a[4], a[5], a[6], bake[1], K[1]);
    P(a[6], a[7], a[0], a[1], a[2], a[3], a[4], a[5], bake[2], K[2]);

    bake[13] = a[4] + S3(a[1]) + F1(a[1], a[2], a[3]) + K[3];
    bake[14] = S2(a[5]) + F0(a[5], a[6], a[7]);
}

// O Loop Brutal (Retorna TRUE se achar o Share de Dificuldade 2 Zeros)
bool nerd_sha256d_baked(const uint32_t* digest, const uint8_t* dataIn, const uint32_t* bake) {
    uint32_t temp1, temp2;
    uint32_t W[64] = { bake[0], bake[1], bake[2], GET_UINT32_BE(dataIn, 12), 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 640 };
    W[16] = bake[3];
    W[17] = bake[4];

    const uint32_t* a = bake + 5;
    uint32_t A[8] = { a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7] };

    temp1 = bake[13] + W[3];
    temp2 = bake[14];
    A[0] += temp1;
    A[4] = temp1 + temp2;

    P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], W[4], K[4]);
    P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], W[5], K[5]);
    P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], W[6], K[6]);
    P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], W[7], K[7]);
    P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], W[8], K[8]);
    P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], W[9], K[9]);
    P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], W[10], K[10]);
    P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], W[11], K[11]);
    P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], W[12], K[12]);
    P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], W[13], K[13]);
    P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], W[14], K[14]);
    P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], W[15], K[15]);
    P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], W[16], K[16]);
    P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], W[17], K[17]);
    P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], R(18), K[18]);
    P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], R(19), K[19]);
    P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], R(20), K[20]);
    P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], R(21), K[21]);
    P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], R(22), K[22]);
    P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], R(23), K[23]);
    P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], R(24), K[24]);
    P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], R(25), K[25]);
    P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], R(26), K[26]);
    P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], R(27), K[27]);
    P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], R(28), K[28]);
    P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], R(29), K[29]);
    P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], R(30), K[30]);
    P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], R(31), K[31]);
    P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], R(32), K[32]);
    P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], R(33), K[33]);
    P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], R(34), K[34]);
    P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], R(35), K[35]);
    P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], R(36), K[36]);
    P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], R(37), K[37]);
    P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], R(38), K[38]);
    P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], R(39), K[39]);
    P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], R(40), K[40]);
    P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], R(41), K[41]);
    P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], R(42), K[42]);
    P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], R(43), K[43]);
    P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], R(44), K[44]);
    P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], R(45), K[45]);
    P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], R(46), K[46]);
    P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], R(47), K[47]);
    P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], R(48), K[48]);
    P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], R(49), K[49]);
    P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], R(50), K[50]);
    P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], R(51), K[51]);
    P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], R(52), K[52]);
    P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], R(53), K[53]);
    P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], R(54), K[54]);
    P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], R(55), K[55]);
    P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], R(56), K[56]);
    
    uint32_t m1 = A[6] + S3(A[3]) + F1(A[3], A[4], A[5]) + K[57] + R(57);
    A[2] += m1;
    uint32_t d57_a1 = A[1];

    uint32_t z1 = A[5] + S3(A[2]) + F1(A[2], A[3], A[4]) + K[58] + R(58);
    uint32_t d58_a0 = A[0];
    A[1] += z1;

    uint32_t t1 = A[4] + S3(A[1]) + F1(A[1], A[2], A[3]) + K[59] + R(59);
    A[0] += t1;

    temp1 = A[3] + S3(A[0]) + F1(A[0], A[1], A[2]) + K[60] + R(60);
    uint32_t a7 = A[7] + temp1;
    
    // O EARLY EXIT! Se não for 0x32E7, ele joga fora e aborta.
    if ((uint32_t)(a7 & 0xFFFF) != 0x32E7) return false;

    // Se passou, é porque cravou os ZEROS perfeitos no final da conta!
    return true;
}

// ============================================================================
// COMUNICAÇÃO SERIAL BITMAIN E MAIN LOOP
// ============================================================================

uint8_t get_crc5(uint8_t *ptr, uint8_t len) {
    uint8_t i, j, crc = 0x1f;
    for (i = 0; i < len; i++) {
        crc ^= ptr[i];
        for (j = 0; j < 8; j++) {
            if (crc & 0x80) crc = (crc << 1) ^ 0x05;
            else crc <<= 1;
        }
    }
    return ((crc >> 3) & 0x1f);
}

void send_bitmain_response(uint32_t nonce) {
    unsigned char buf_nonce[11] = {0xAA, 0x55, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0};
    buf_nonce[4] = (nonce >> 24) & 0xFF;
    buf_nonce[5] = (nonce >> 16) & 0xFF;
    buf_nonce[6] = (nonce >> 8)  & 0xFF;
    buf_nonce[7] = (nonce >> 0)  & 0xFF;
    buf_nonce[10] = get_crc5(buf_nonce, 10);
    uart_write_bytes(SIM_UART_PORT, buf_nonce, 11);
}

static void asic_simulator_task(void *arg) {
    uart_config_t uart_config = {
        .baud_rate = 115200, .data_bits = UART_DATA_8_BITS, .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1, .flow_ctrl = UART_HW_FLOWCTRL_DISABLE, .source_clk = UART_SCLK_DEFAULT,
    };
    ESP_ERROR_CHECK(uart_param_config(SIM_UART_PORT, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(SIM_UART_PORT, SIM_TXD_PIN, SIM_RXD_PIN, -1, -1));
    ESP_ERROR_CHECK(uart_driver_install(SIM_UART_PORT, BUF_SIZE * 2, BUF_SIZE * 2, 0, NULL, 0));

    uint8_t *data = (uint8_t *)malloc(BUF_SIZE);
    ESP_LOGI(TAG, "ASIC Músculo (CÓDIGO EXTREMO) Iniciado!");

    while (1) {
        int len = uart_read_bytes(SIM_UART_PORT, data, 128, 20 / portTICK_PERIOD_MS);
        if (len > 0) {
            data[len] = '\0';
            if (strstr((char*)data, "PING") != NULL) {
                uart_write_bytes(SIM_UART_PORT, "PONG", 4); continue;
            }

            if (len >= 6) {
                if (data[2] == 0x52 && data[5] == 0x00) {
                    unsigned char buf_id[11] = {0,0,0,0,0,0,0,0,0,0,1}; uart_write_bytes(SIM_UART_PORT, buf_id, 11);
                }
                else if (data[2] == 0x51 && data[5] == 0x28) {
                    uart_wait_tx_done(SIM_UART_PORT, 1000 / portTICK_PERIOD_MS);
                    uart_set_baudrate(SIM_UART_PORT, 1000000);
                }
                else if (data[2] == 0x21) {
                    ESP_LOGW(TAG, "=> SEND_WORK Recebido! Iniciando Baking...");
                    uart_flush(SIM_UART_PORT);

                    // 1. Extrai o Midstate (32 bytes) do pacote e converte para INTEIROS de 32 Bits (Big Endian)
                    uint32_t digest[8];
                    for(int i=0; i<8; i++) {
                        digest[i] = GET_UINT32_BE((&data[4]), i*4);
                    }
                    
                    // 2. Extrai o Tail (12 bytes) e prepara o Bloco final (16 bytes)
                    uint8_t dataIn[16] = {0};
                    memcpy(dataIn, &data[36], 12); 
                    
                    // 3. A MÁGICA: O BAKING! (Precalcula a parte invariável e salva no array)
                    uint32_t bake_array[15];
                    nerd_sha256_bake(digest, dataIn, bake_array);
                    
                    uint32_t nonce = 0, hashes_calculated = 0;
                    uint32_t start_time = xTaskGetTickCount();
                    
                    while (1) {
                        if (hashes_calculated % 2000 == 0) vTaskDelay(1); 
                        
                        size_t available = 0;
                        uart_get_buffered_data_len(SIM_UART_PORT, &available);
                        if (available > 0) break; 
                        
                        // O Cérebro (S3) insere o Nonce de forma sequencial nos bytes do cabeçalho
                        dataIn[12] = (nonce >> 0) & 0xFF;
                        dataIn[13] = (nonce >> 8) & 0xFF;
                        dataIn[14] = (nonce >> 16) & 0xFF;
                        dataIn[15] = (nonce >> 24) & 0xFF;
                        
                        // A LOUCURA: Se a função retornar TRUE, o Early Exit comprovou o Share!
                        if (nerd_sha256d_baked(digest, dataIn, bake_array)) {
                            ESP_LOGI(TAG, "Hardware Share (Early Exit Pass)! Enviando Nonce: %08lx", (unsigned long)nonce);
                            send_bitmain_response(nonce);
                        }
                        
                        nonce++; hashes_calculated++;

                        if (hashes_calculated % 100000 == 0) {
                            uint32_t diff_ms = (xTaskGetTickCount() - start_time) * portTICK_PERIOD_MS;
                            uint32_t hr = (hashes_calculated * 1000) / (diff_ms > 0 ? diff_ms : 1);
                            ESP_LOGI(TAG, "Velocidade Músculo: %lu H/s", (unsigned long)hr);
                        }
                    }
                }
            }
        }
    }
}

void app_main(void) {
    xTaskCreate(asic_simulator_task, "asic_sim_task", 8192, NULL, 10, NULL);
}