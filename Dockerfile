# 4tail - all-in-one image with the recon toolset preinstalled.
#   docker build -t 4tail .
#   docker run --rm -it 4tail -C -j -A example.com
#   docker run --rm -e TOGETHER_API_KEY=sk-... 4tail -C -j example.com
FROM golang:1.22-bookworm AS tools
ENV GOBIN=/out GO111MODULE=on CGO_ENABLED=0
RUN mkdir -p /out && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest && \
    go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/tomnomnom/gf@latest && \
    go install github.com/tomnomnom/qsreplace@latest && \
    go install github.com/tomnomnom/unfurl@latest && \
    go install github.com/hahwul/dalfox/v2@latest && \
    go install github.com/Emoe/kxss@latest && \
    go install github.com/lc/subjs@latest && \
    go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      bash curl jq ca-certificates python3 python3-pip pipx git seclists \
      dnsutils less ncurses-bin && \
    rm -rf /var/lib/apt/lists/*
# Python-based specialists (best-effort; the script degrades gracefully if any are missing).
RUN pipx install corsy || true && \
    pipx install waymore || true && \
    pipx install arjun || true && \
    pipx install git-dumper || true
ENV PATH="/root/.local/bin:/usr/local/bin:${PATH}" \
    SECLISTS_DIR="/usr/share/seclists"
COPY --from=tools /out/* /usr/local/bin/
# gf patterns (for the gf bucketing stage)
RUN git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /root/.gf 2>/dev/null || true
# nuclei templates (first run would fetch them anyway; bake them in)
RUN nuclei -update-templates -silent 2>/dev/null || true
WORKDIR /opt/4tail
COPY . /opt/4tail
RUN chmod +x 4tail.sh lib/*.sh 2>/dev/null || true
ENTRYPOINT ["/opt/4tail/4tail.sh"]
