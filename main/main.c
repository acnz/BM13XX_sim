#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"

#define SIM_TXD_PIN 4 
#define SIM_RXD_PIN 5
#define SIM_UART_PORT UART_NUM_1
#define BUF_SIZE 1024

static const char *TAG = "ASIC_MUSCULO";

// ============================================================================
// NÚCLEO SHA-256 PURO (LÓGICA DO NERDMINER / CGMINER)
// ============================================================================
static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

// Transforma o estado do SHA256 processando 1 bloco (64 bytes)
void sha256_transform(uint32_t *state, const uint8_t *data) {
    uint32_t a, b, c, d, e, f, g, h, i, T1, T2;
    uint32_t W[64];

    for (i = 0; i < 16; i++) {
        W[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) | (data[i * 4 + 2] << 8) | data[i * 4 + 3];
    }
    for (i = 16; i < 64; i++) {
        W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 64; i++) {
        T1 = h + EP1(e) + CH(e, f, g) + sha256_k[i] + W[i];
        T2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// A Magia do Midstate: Calcula apenas a 2ª metade do hash!
void calculate_hash_from_midstate(const uint8_t *midstate, const uint8_t *tail, uint32_t nonce, uint8_t *out_hash) {
    uint32_t state[8];
    // 1. Carrega o Midstate (32 bytes) para o Estado Interno
    for (int i = 0; i < 8; i++) {
        state[i] = (midstate[i*4] << 24) | (midstate[i*4+1] << 16) | (midstate[i*4+2] << 8) | midstate[i*4+3];
    }

    // 2. Prepara o Bloco 2 (Resto do Cabeçalho + Padding de tamanho)
    uint8_t block2[64] = {0};
    memcpy(block2, tail, 12);
    block2[12] = (nonce >> 0) & 0xFF;
    block2[13] = (nonce >> 8) & 0xFF;
    block2[14] = (nonce >> 16) & 0xFF;
    block2[15] = (nonce >> 24) & 0xFF;
    block2[16] = 0x80; // Início do preenchimento
    block2[62] = 0x02; // Tamanho total em bits (640 bits = 0x0280)
    block2[63] = 0x80;

    // 3. Roda a transformação APENAS no Bloco 2!
    sha256_transform(state, block2);

    // 4. Prepara para o Duplo SHA-256
    uint8_t hash1[32];
    for (int i = 0; i < 8; i++) {
        hash1[i*4]   = (state[i] >> 24) & 0xFF;
        hash1[i*4+1] = (state[i] >> 16) & 0xFF;
        hash1[i*4+2] = (state[i] >> 8)  & 0xFF;
        hash1[i*4+3] = (state[i] >> 0)  & 0xFF;
    }

    // O Segundo SHA-256 é normal, usamos a mbedtls para poupar código
    mbedtls_sha256(hash1, 32, out_hash, 0);
}

// ============================================================================
// COMUNICAÇÃO SERIAL BITMAIN
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
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    ESP_ERROR_CHECK(uart_param_config(SIM_UART_PORT, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(SIM_UART_PORT, SIM_TXD_PIN, SIM_RXD_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    ESP_ERROR_CHECK(uart_driver_install(SIM_UART_PORT, BUF_SIZE * 2, BUF_SIZE * 2, 0, NULL, 0));

    uint8_t *data = (uint8_t *)malloc(BUF_SIZE);
    ESP_LOGI(TAG, "ASIC Músculo (NerdMiner Logic) Iniciado!");

    while (1) {
        int len = uart_read_bytes(SIM_UART_PORT, data, 128, 20 / portTICK_PERIOD_MS);
        if (len > 0) {
            data[len] = '\0';

            if (strstr((char*)data, "PING") != NULL) {
                uart_write_bytes(SIM_UART_PORT, "PONG", 4);
                uart_flush(SIM_UART_PORT);
                continue;
            }

            if (len >= 6) {
                if (data[2] == 0x52 && data[5] == 0x00) {
                    unsigned char buf_id[11] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
                    uart_write_bytes(SIM_UART_PORT, buf_id, 11);
                }
                else if (data[2] == 0x51 && data[5] == 0x28) {
                    ESP_ERROR_CHECK_WITHOUT_ABORT(uart_wait_tx_done(SIM_UART_PORT, 1000 / portTICK_PERIOD_MS));
                    ESP_ERROR_CHECK_WITHOUT_ABORT(uart_set_baudrate(SIM_UART_PORT, 1000000));
                }
                else if (data[2] == 0x21) { // PROTOCOLO ORIGINAL 70 BYTES!
                    ESP_LOGW(TAG, "=> SEND_WORK (0x21) Recebido! Fritando silício a partir do Midstate...");
                    uart_flush(SIM_UART_PORT);

                    uint8_t midstate[32];
                    uint8_t tail[12];
                    memcpy(midstate, &data[4], 32); 
                    memcpy(tail, &data[36], 12); 
                    
                    uint8_t hash_final[32];
                    uint32_t nonce = 0, hashes_calculated = 0;
                    uint32_t start_time = xTaskGetTickCount();
                    
                    while (1) {
                        // Watchdog (Alivia a cada 2000 hashes)
                        if (hashes_calculated % 2000 == 0) vTaskDelay(1); 

                        // Aborta se o S3 mandar pacote novo
                        size_t available = 0;
                        uart_get_buffered_data_len(SIM_UART_PORT, &available);
                        if (available > 0) break; 
                        
                        // AQUI É A MÁGICA: Gera o hash usando só a metade final!
                        calculate_hash_from_midstate(midstate, tail, nonce, hash_final);
                        
                        // DIFICULDADE DO HARDWARE (2 Bytes Zerados = 1 chance em 65 mil)
                        // Vai enviar nonces pro S3 frequentemente, e o S3 decide se a Pool aceita ou não.
                        if (hash_final[31] == 0x00 && hash_final[30] == 0x00) {
                            ESP_LOGI(TAG, "Hardware Share Achado! Repassando p/ o S3 avaliar. Nonce: %08lx", (unsigned long)nonce);
                            send_bitmain_response(nonce);
                        }
                        
                        nonce++;
                        hashes_calculated++;

                        // Relatório de Velocidade
                        if (hashes_calculated % 50000 == 0) {
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