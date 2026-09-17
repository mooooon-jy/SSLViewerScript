# SSL Certificate Watch

RHEL 9.3 폐쇄망에서 `openssl s_client`로 도메인:포트별 SSL 인증서 등록일과 만료기한을 조회하는 로컬 웹 화면입니다.

## 폐쇄망 반입 파일

다음 세 파일을 같은 디렉터리에 복사합니다.

- `server.py`
- `index.html`
- `업무망_내부.md`
- `export-ssl-results.ps1` (Windows에서 운영 결과 생성 시)
- `ssl-results.json` (Windows 운영 조회 결과를 반입한 경우)

Python 패키지 설치는 필요하지 않습니다.

## RHEL 9.3 실행

OpenSSL과 Python 버전을 확인합니다.

```bash
python3 --version
openssl version
```

서버를 실행합니다.

```bash
python3 server.py
```

서버를 실행하면 먼저 Linux에서 인증서를 한 번 자동 조회한 뒤 웹 서버를 시작합니다. `ssl-results.json`에 Windows 반입 결과가 있는 대상은 유지하고, 반입 결과가 없는 대상만 Linux OpenSSL로 조회합니다. 조회가 끝난 뒤 페이지를 열면 결과가 고정되어 표시됩니다.

기본적으로 최대 8개 대상을 동시에 조회하고 대상별 timeout은 5초입니다. 네트워크 환경에 맞춰 다음처럼 조정할 수 있습니다.

```bash
SSL_CHECK_WORKERS=4 SSL_CHECK_TIMEOUT=10 python3 server.py
```

브라우저에서 접속합니다.

```text
http://127.0.0.1:8084
```

서버를 종료하려면 실행 중인 터미널에서 `Ctrl+C`를 누릅니다.

## 내부망의 다른 PC에서 접속

서버가 설치된 RHEL 장비의 IP로 다른 PC에서도 접속해야 하는 경우에만 다음처럼 실행합니다.

```bash
SSL_VIEWER_HOST=0.0.0.0 SSL_VIEWER_PORT=8084 python3 server.py
```

그 후 방화벽에서 8765/tcp 접근을 허용하고 아래 주소로 접속합니다.

```text
http://RHEL서버IP:8084
```

## 실행 명령

각 대상 조회 시 서버 내부에서 다음과 같은 흐름으로 실행합니다.

```bash
echo | openssl s_client \
  -connect 도메인:포트 \
  -servername 도메인 2>/dev/null | \
  openssl x509 -noout -dates
```

인증서 조회 대상은 `업무망_내부.md`의 `Port(SSL)` 값이 있는 행에서 자동으로 생성됩니다. `Port(SSL)`에 `1935, 8443`처럼 여러 포트가 있으면 각각 별도 대상으로 표시됩니다.

## 주의사항

- RHEL 서버에서 대상 도메인으로 연결할 수 있어야 합니다.
- `openssl` 명령이 PATH에 있어야 합니다. 보통 RHEL 9.3에는 기본 설치되어 있습니다.
- 서버를 재실행하면 화면에서 조회한 결과는 초기화됩니다.
- `ssl-results.json`을 함께 두면 Linux에서 운영 조회 결과를 초기 화면에 표시합니다.
- 외부 CDN이나 외부 Python 패키지를 사용하지 않으므로 폐쇄망에서도 화면 자체를 실행할 수 있습니다.

## 운영 환경에서 인증서 조회 실패 시

개발/QA는 정상이고 운영만 실패하면 해당 운영 포트가 실제 TLS 포트인지 먼저 확인합니다. RHEL 서버에서 실패한 대상의 도메인과 포트로 실행합니다.

```bash
echo | openssl s_client \
  -connect 운영도메인:포트 \
  -servername 운영도메인 2>/dev/null | \
  openssl x509 -noout -dates
```

다음과 같이 원인을 확인할 수 있습니다.

```bash
openssl s_client -connect 운영도메인:포트 -servername 운영도메인 </dev/null
```

- `Connection refused`, `timed out`: 운영 서버의 포트 접근 또는 방화벽 문제입니다.
- `wrong version number`: 해당 포트가 HTTPS/TLS 포트가 아니거나 평문 HTTP 포트입니다.
- `no peer certificate available`: 서버가 인증서를 내보내지 않거나 TLS 협상이 실패한 것입니다.
- `handshake failure`: TLS 버전, 암호화 방식 또는 SNI 설정을 운영 서버가 거부한 것입니다.

코드 업데이트 후에는 반드시 기존 서버를 `Ctrl+C`로 종료하고 `python3 server.py`로 다시 실행해야 합니다.

## Windows 운영 결과를 Linux로 반입

Windows에서 아래 스크립트를 `업무망_내부.md`와 같은 폴더에 둡니다.

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\export-ssl-results.ps1 -InputFile .\업무망_내부.md -OutputFile .\ssl-results.json
```

스크립트는 `운영` 환경 행만 조회합니다. 각 행의 `IP Address`로 연결하고 `도메인`을 TLS SNI로 사용하므로, Windows에서만 접근 가능한 운영 경로를 그대로 이용할 수 있습니다.

생성된 `ssl-results.json`을 `server.py`, `index.html`, `업무망_내부.md`와 함께 Linux에 복사한 뒤 서버를 재실행합니다.

Linux 페이지 상단에 `결과 YYYY-MM-DD HH:mm:ss UTC`가 표시되면 반입 결과를 읽은 상태입니다. 조회 실패한 운영 대상도 JSON에 `ok: false`와 `error`로 저장되어 화면에서 확인할 수 있습니다.
