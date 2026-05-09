#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"

// --- CONFIGURAÇÃO DOS PINOS DO ESP32-C3 ---
#define SIM_TXD_PIN 4
#define SIM_RXD_PIN 5
#define SIM_UART_PORT UART_NUM_1
#define BUF_SIZE 1024

static const char *TAG = "ASIC_SIMULATOR";

// Função oficial de CRC5 da Bitmain
uint8_t get_crc5(uint8_t *ptr, uint8_t len)
{
    uint8_t i, j;
    uint8_t crc = 0x1f;
    for (i = 0; i < len; i++)
    {
        crc ^= ptr[i];
        for (j = 0; j < 8; j++)
        {
            if (crc & 0x80)
                crc = (crc << 1) ^ 0x05;
            else
                crc <<= 1;
        }
    }
    return ((crc >> 3) & 0x1f);
}

// Função que compara se o hash atual é "melhor" (menor valor numérico) que o melhor registrado
bool is_hash_better(uint8_t *current_hash, uint8_t *best_hash)
{
    // Como os zeros significativos ficam no final do array no ESP32, lemos de trás para frente
    for (int i = 31; i >= 0; i--)
    {
        if (current_hash[i] < best_hash[i])
            return true; // É melhor!
        if (current_hash[i] > best_hash[i])
            return false; // É pior!
    }
    return false; // São iguais
}

// Função para empacotar e enviar a resposta do Nonce no padrão Bitmain
void send_bitmain_response(uint32_t nonce)
{
    unsigned char buf_nonce[11] = {0xAA, 0x55, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0};

    // Desmonta o Nonce (32 bits) para 4 bytes isolados
    buf_nonce[4] = (nonce >> 24) & 0xFF;
    buf_nonce[5] = (nonce >> 16) & 0xFF;
    buf_nonce[6] = (nonce >> 8) & 0xFF;
    buf_nonce[7] = (nonce >> 0) & 0xFF;

    // Calcula CRC5 e adiciona no último byte
    buf_nonce[10] = get_crc5(buf_nonce, 10);

    // Dispara pela porta Serial de volta para o S3
    uart_write_bytes(SIM_UART_PORT, buf_nonce, 11);
}

static void asic_simulator_task(void *arg)
{
    uart_config_t uart_config = {
        .baud_rate = 115200, // Começa a 115200 (Padrão de boot Bitmain)
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

    ESP_LOGI(TAG, "Simulador BM13xx Iniciado. Aguardando ESP-Miner...");

    while (1)
    {
        // Lê os bytes recebidos pela UART
        int len = uart_read_bytes(SIM_UART_PORT, data, 128, 20 / portTICK_PERIOD_MS);

        if (len > 0)
        {
            data[len] = '\0'; // Terminador nulo para strings

            // --- 0. TESTE DE PING-PONG ---
            if (strstr((char *)data, "PING") != NULL)
            {
                ESP_LOGW(TAG, "=> Detectado: Texto 'PING' recebido!");
                uart_write_bytes(SIM_UART_PORT, "PONG", 4);
                ESP_LOGI(TAG, "<= Respondido: 'PONG'");
                uart_flush(SIM_UART_PORT);
                continue;
            }

            if (len >= 6)
            {
                // --- 1. COMANDO READ_REG (Identificação) ---
                if (data[2] == 0x52 && data[5] == 0x00)
                {
                    ESP_LOGI(TAG, "=> Detectado: READ_REG (Enviando Chip ID)");
                    unsigned char buf_id[11] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
                    uart_write_bytes(SIM_UART_PORT, buf_id, 11);
                }
                // --- 2. COMANDO WRITE_REG (Baudrate) ---
                else if (data[2] == 0x51 && data[5] == 0x28)
                {
                    ESP_LOGI(TAG, "=> Detectado: Mudança de Baudrate para 1.000.000");
                    ESP_ERROR_CHECK_WITHOUT_ABORT(uart_wait_tx_done(SIM_UART_PORT, 1000 / portTICK_PERIOD_MS));
                    ESP_ERROR_CHECK_WITHOUT_ABORT(uart_set_baudrate(SIM_UART_PORT, 1000000));
                }
                // --- 3. COMANDO SEND_WORK (0x21) - O PROTOCOLO DE 70 BYTES ---
                else if (data[2] == 0x21)
                {
                    ESP_LOGW(TAG, "=> SEND_WORK (0x21) Recebido! Iniciando Mineração com Hierarquia...");
                    uart_flush(SIM_UART_PORT);

                    uint8_t hash1[32], hash2[32];
                    uint32_t nonce = 0, hashes_calculated = 0;

                    // Monta um cabeçalho fictício de 80 bytes para a mbedtls processar
                    // Usamos os 32 bytes do Midstate e os 12 bytes finais recebidos do pacote 0x21
                    uint8_t dummy_header[80] = {0};
                    memcpy(&dummy_header[36], &data[4], 32);  // Midstate
                    memcpy(&dummy_header[68], &data[36], 12); // Resto do cabeçalho

                    // --- VARIÁVEIS DA HIERARQUIA ---
                    uint32_t best_nonce = 0;
                    uint8_t best_hash[32];
                    memset(best_hash, 0xFF, 32); // Começa com o "pior" hash possível

                    uint32_t timer_10s = xTaskGetTickCount(); // Cronômetro de 10 segundos

                    while (1)
                    {
                        // Respiro do Watchdog (1ms de folga a cada 2000 hashes)
                        if (hashes_calculated % 2000 == 0)
                        {
                            vTaskDelay(1);
                        }

                        // Aborta imediatamente se o S3 mandar um bloco novo pela Serial
                        size_t available = 0;
                        uart_get_buffered_data_len(SIM_UART_PORT, &available);
                        if (available > 0)
                        {
                            ESP_LOGW(TAG, "Novo bloco na UART. Abortando cálculo atual.");
                            break;
                        }

                        // Injeta o Nonce atual
                        dummy_header[76] = (nonce >> 0) & 0xFF;
                        dummy_header[77] = (nonce >> 8) & 0xFF;
                        dummy_header[78] = (nonce >> 16) & 0xFF;
                        dummy_header[79] = (nonce >> 24) & 0xFF;

                        // Hash Duplo
                        mbedtls_sha256(dummy_header, 80, hash1, 0);
                        mbedtls_sha256(hash1, 32, hash2, 0);

                        // NÍVEL 1 e NÍVEL 2 (Apenas Hashes Válidos!)
                        bool is_network_block = (hash2[31] == 0 && hash2[30] == 0 && hash2[29] == 0 && hash2[28] == 0);
                        bool is_pool_share = (hash2[31] == 0 && hash2[30] == 0 && hash2[29] == 0);

                        if (is_network_block || is_pool_share)
                        {
                            ESP_LOGW(TAG, "SHARE VÁLIDO ENCONTRADO! Nonce: %08lx", (unsigned long)nonce);
                            send_bitmain_response(nonce);
                            // E ele continua minerando em silêncio sem dar break!
                        }

                        nonce++;
                        hashes_calculated++;
                    }
                }
            }
        }
    }
}

void app_main(void)
{
    // Aumentamos o tamanho do stack da tarefa para suportar a biblioteca mbedtls tranquilamente
    xTaskCreate(asic_simulator_task, "asic_sim_task", 8192, NULL, 10, NULL);
}