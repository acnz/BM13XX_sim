# BM13XX_sim: Emulador Híbrido de ASIC Bitmain no ESP32

## 🚀 Sobre o Projeto
O **BM13XX_sim** é um core de Mineração de Bitcoin desenvolvido sobre o framework ESP-IDF para o ESP32. O objetivo do projeto é **emular perfeitamente o comportamento de uma ASIC da série BM13XX da Bitmain**, respondendo aos comandos de uma controladora original via comunicação UART (baseado no protocolo Stratum/BM).

## 🧠 Arquitetura Híbrida (A "Mágica")
O grande desafio deste projeto foi contornar uma limitação de hardware do ESP32: o acelerador criptográfico nativo não possui documentação/suporte para aceitar a injeção de um estado intermediário (**midstate**) do algoritmo SHA-256. Como o protocolo oficial da Bitmain envia apenas o *midstate* pela UART (para economizar banda), fomos forçados a criar uma **Arquitetura Híbrida** para o cálculo do Duplo SHA-256:

1. **Primeiro Hash (Via Software - CPU):**
   A controladora envia o *midstate* (32 bytes) e os dados finais do Header (12 bytes). Como o hardware do ESP32 exige iniciar hashes "do zero", resolvemos essa primeira etapa via software puro na CPU, utilizando as técnicas hiper-otimizadas de *baking* derivadas do NerdMiner.
2. **Segundo Hash (Via Hardware - Acelerador DPORT):**
   O resultado do Hash 1 (exatos 32 bytes) entra como input para o segundo hash. O código injeta esses bytes diretamente na memória física do acelerador (`SHA_TEXT_BASE`) e aciona os registradores (`SHA_START_REG`) em C puro. O hardware absorve o processamento e devolve o hash final em velocidade de silício.

### ⚙️ Estrutura de Núcleos (Multiprocessing)
* **Core 0 (O Maestro & Operário 0):** Roda a task `uart_listener_task` que negocia baudrate, atende PING/PONG e atualiza o trabalho global (`g_job_version`). Concorrentemente, minera os nonces **pares**.
* **Core 1 (O Operário 1):** Dedicado 100% à mineração em loop de alta velocidade, responsável por testar os nonces **ímpares**.

## 📊 Performance e Limites (O Teto de Vidro)
Com a abordagem híbrida, o ESP32 atingiu a marca formidável de **~80 kH/s (40 kH/s por núcleo)** mantendo total fidelidade à API da Bitmain.

**Por que não 700+ kH/s como em outros projetos (ex: BitsyMiner)?**
A resposta reside na **Lei de Amdahl**. Projetos ultra-rápidos abdicam da arquitetura da Bitmain: eles geram o Header de 80 bytes completo e empurram *tudo* direto para o hardware. Para continuarmos sendo um emulador "Drop-In" (plug-and-play em chicotes Bitmain), nós **precisamos** aceitar o *midstate*. Isso nos obriga a rodar o primeiro hash via CPU (gastando cerca de 6.000 ciclos de clock). A CPU é o nosso gargalo intransponível.

## 🔮 Próximos Passos (A Rota para a FPGA)
O `BM13XX_sim` atual prova o conceito e exaure matematicamente o limite do chip ESP32 para este caso de uso específico. 

O próximo passo arquitetural é portar essa lógica para uma **FPGA** (como Lattice iCE40, Xilinx Spartan ou Zynq). Através de VHDL/Verilog, será possível instanciar um bloco SHA-256 customizado com portas exclusivas para *injetar o midstate nativamente em hardware*. Paralelizando o processo, a arquitetura deixará a escala de kH/s para alcançar a casa dos **MH/s**.

---
*Este código representa a ponte definitiva e o limite físico entre o mundo dos microcontroladores (software) e o funcionamento real de uma ASIC de Bitcoin.*