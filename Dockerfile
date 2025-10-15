# Use Ubuntu 22.04 as base image for better compatibility with LLVM 18
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies including LLVM build requirements and zsh
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    python3 \
    python3-pip \
    python3-dev \
    wget \
    unzip \
    curl \
    ninja-build \
    clang \
    libclang-dev \
    llvm \
    llvm-dev \
    lld \
    libc6-dev \
    binutils \
    zlib1g-dev \
    libncurses5-dev \
    libxml2-dev \
    libedit-dev \
    libffi-dev \
    zsh \
    flex \
    libncurses-dev \
    bison \
    libssl-dev \
    libelf-dev \
    libdw-dev \
    dwarves \
    bc \
    vim \
    xz-utils \
    tar \
    cpio \
    pkg-config \
    libgtk-3-dev libglib2.0-dev libpango1.0-dev libharfbuzz-dev \
    libfreetype6-dev libfontconfig1-dev libgdk-pixbuf-2.0-dev \
    libicu-dev libpng-dev libjpeg-turbo8-dev libtiff-dev \
    autoconf2.13 nasm yasm zip \
    python3-venv \
    libx11-dev libx11-xcb-dev libxcb1-dev libxcb-shm0-dev \
    libxext-dev libxrandr-dev libxcomposite-dev libxcursor-dev \
    libxdamage-dev libxfixes-dev libxi-dev libxtst-dev \
    mesa-common-dev libegl1-mesa-dev libopengl-dev \
    libasound2-dev libpulse-dev \
    libdbus-1-dev libdbus-glib-1-dev \
    zlib1g-dev libffi-dev \

    && rm -rf /var/lib/apt/lists/*

# Install Oh My Zsh for prettier shell
RUN sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended

# Install Nodejs 20
RUN set -eux; \
  mkdir -p /etc/apt/keyrings; \
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg; \
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list; \
  apt-get update; \
  apt-get install -y --no-install-recommends nodejs; \
  node -v && npm -v; \
  rm -rf /var/lib/apt/lists/*

# Rust set up
RUN set -eux; \
  curl -fsSL https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.82.0; \
  rustc --version && cargo --version; \
  apt-get -y purge cbindgen || true; \
  cargo install cbindgen --version 0.26.0 --force; \
  cbindgen --version

# Set zsh as default shell
RUN chsh -s $(which zsh)

# Configure Oh My Zsh with a theme that shows current directory and useful plugins
RUN sed -i 's/ZSH_THEME="robbyrussell"/ZSH_THEME="bira"/' ~/.zshrc \
    && sed -i 's/plugins=(git)/plugins=(git python pip docker docker-compose colored-man-pages command-not-found)/' ~/.zshrc

# Create working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the project
COPY . .

# Initialize git submodules (for tree-sitter) - handle both git repo and archive cases
RUN if [ -d .git ]; then \
        git submodule update --init --recursive; \
    else \
        echo "Not a git repo, checking tree-sitter-cpp..."; \
        if [ ! -d "src/kparser/tree-sitter-cpp/.git" ]; then \
            echo "Setting up tree-sitter-cpp..."; \
            cd src/kparser && \
            rm -rf tree-sitter-cpp && \
            git clone https://github.com/tree-sitter/tree-sitter-cpp.git; \
        else \
            echo "tree-sitter-cpp already exists"; \
        fi; \
    fi

# Set back to main working directory
WORKDIR /app

# Default command
CMD ["/bin/zsh"]
