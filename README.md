# NoskNet Diagnostic

**Ferramenta de diagnóstico técnico de rede para Garena Free Fire**  
Package alvo: `com.dts.freefireth`

> **Milestone 1** — Protótipo mínimo de VpnService + passthrough  
> Objetivo: provar que o Free Fire continua funcionando com o tráfego passando pelo TUN local, restrito apenas a ele.

---

## O que este Milestone 1 faz

- Solicita autorização de VPN
- Cria interface TUN
- Restringe **exclusivamente** o package `com.dts.freefireth` com `addAllowedApplication`
- Faz passthrough (encaminhamento) dos pacotes
- Evita loop de VPN com `protect()`
- Mostra estados claros da VPN
- Conta pacotes e mostra logs básicos
- Não armazena payload
- Não modifica nenhum pacote do Free Fire

## O que este Milestone 1 **ainda não** faz

- Análise completa de metadados (IP, porta, endpoints agregados)
- Detecção automática de anomalias
- Botão “LAG AGORA”
- Persistência de sessão + exportação TXT/CSV/JSON
- Encaminhamento TCP completo (máquina de estados)
- Modo passivo (sem VPN)

Esses itens entram a partir do Milestone 2.

---

## Arquitetura atual

```
ui/
  MainActivity.kt          → UI mínima + controle de estados

service/
  NoskVpnService.kt        → VpnService + TUN + passthrough
  VpnState.kt              → Estados da VPN
```

---

## Como o VpnService é configurado (ponto crítico)

```kotlin
Builder()
    .setSession("NoskNet Diagnostic")
    .addAddress("10.8.0.2", 32)
    .addRoute("0.0.0.0", 0)
    .addAllowedApplication("com.dts.freefireth")   // ← só o Free Fire
    .setMtu(1500)
```

- `addAllowedApplication("com.dts.freefireth")` → **somente** o Free Fire é roteado para o TUN.
- Todos os outros aplicativos continuam usando a rede normal.

### Proteção contra loop

Todo socket de saída usado para reenviar pacotes é protegido:

```kotlin
protect(socket)
```

Sem isso, o tráfego de saída do próprio serviço voltaria para o TUN → loop infinito → Free Fire sem internet.

---

## Build

### Pré-requisitos
- Android Studio Hedgehog ou mais recente
- JDK 17
- Android SDK 35

### Compilar

```bash
./gradlew assembleDebug
```

O APK fica em:

```
app/build/outputs/apk/debug/app-debug.apk
```

---

## Instalação

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Ou instale manualmente pelo arquivo APK.

---

## Teste obrigatório (Milestone 1)

1. Abra o **NoskNet Diagnostic**
2. Toque em **INICIAR CAPTURA**
3. Aceite a autorização de VPN
4. Abra o **Free Fire** e entre em uma partida real
5. Observe:
   - O estado muda para `VPN: CAPTURANDO`
   - Contador de pacotes sobe
   - Logs aparecem com IP/porta/protocolo
6. O Free Fire **deve continuar com internet normal**
7. Toque em **PARAR CAPTURA**

### Critérios de sucesso do Milestone 1

- [x] VPN autorizada
- [x] TUN criado
- [x] Apenas Free Fire direcionado
- [x] Free Fire continua jogável (sem perda total de conexão)
- [x] Contador de pacotes aumenta
- [x] Estados da VPN funcionam
- [x] Parar a VPN funciona corretamente

---

## Limitações técnicas (honestas)

- RTT real do Free Fire **não é determinável** apenas observando o TUN.
- Ausência de pacotes **não** significa packet loss.
- Variação de intervalo **não** é chamada de “jitter de rede” sem evidência.
- O próprio VpnService introduz overhead (cópia de memória + processamento).  
  Os dados observados são “através do caminho VPN”, não o caminho original do jogo.
- Encaminhamento TCP completo ainda não está implementado (Milestone 2).

---

## Próximos passos (Milestone 2)

- Captura completa de metadados (timestamp, direção, IP, porta, protocolo, tamanho)
- Agregação por endpoint
- SessionManager
- AnomalyDetector
- LagMarker (“LAG AGORA”)
- Persistência + exportação

---

## Licença

Uso exclusivamente para diagnóstico técnico pessoal.  
Não modificar, injetar ou interferir no Free Fire.
