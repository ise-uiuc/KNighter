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
    && rm -rf /var/lib/apt/lists/*

# Install Oh My Zsh for prettier shell
RUN sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended

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
