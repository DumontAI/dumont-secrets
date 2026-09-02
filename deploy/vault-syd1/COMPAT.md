# Compat watch — Dumont Secrets

Chrome atualiza a extensão Bitwarden sozinho. O cofre **não** sobe em `:latest` e **não** tem apply automático no vault-syd1 (migração de DB sem rollback fácil).

O que é automático: detectar atraso, abrir card no Hangar (SEC) e avisar no Chat.  
O que não é: `docker pull` / recreate no host. Isso continua janela + backup. A imagem até pode nascer no CI (`dumont-release.yml` no tag `v*-dumont.*`).

## Destinos

- Hangar projeto [Dumont Secrets (SEC)](https://hangar.getdumont.ai/dumont/projects/ac913f1a-fa7f-4c98-848b-b0ae826f7117/issues)
- Dumont Chat canal `#alerts-dumont-secrets`
- GitHub Action `Compat watch` — só manual (`workflow_dispatch`); o diário é o timer na hel1
- Units: [`deploy/hel1-watch/`](../hel1-watch/) → `/etc/systemd/system/` na hel1
- Cópia do script: `/home/deploy/dumont-secrets-watch/` (PIN.json + compat-watch.py)

## Depois de um bump no host

1. Atualizar `PIN.json` + esta tabela em `VERSIONING.md`
2. Staff: **logout** na extensão (não só lock) → Self-hosted `https://secret.getdumont.ai` → Use SSO
3. Rodar `python3 deploy/vault-syd1/compat-watch.py --notify --force` na hel1 para fechar o ciclo no canal
