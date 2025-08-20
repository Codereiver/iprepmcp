FROM python:3.11-slim

# Install system dependencies as root
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN adduser --disabled-password --gecos '' --uid 1000 iprep

# Set working directory and change ownership
WORKDIR /app
RUN chown iprep:iprep /app

# Switch to non-root user
USER iprep

# Clone the iprep repository
RUN git clone https://github.com/Codereiver/iprep.git

# Copy requirements and change ownership
COPY --chown=iprep:iprep requirements.txt .

# Install Python dependencies
RUN pip install --user --no-cache-dir -r requirements.txt

# Install iprep dependencies
RUN pip install --user --no-cache-dir -r iprep/requirements.txt

# Copy the MCP server
COPY --chown=iprep:iprep mcp_server.py .

# Add user's pip bin to PATH
ENV PATH=/home/iprep/.local/bin:$PATH

# Set environment variables for iprep configuration
ENV PYTHONUNBUFFERED=1
ENV IPREP_DEBUG=false
ENV IPREP_ACTIVE_MODE=false

# Expose the MCP server (stdio based, no port needed)
# The server communicates via stdio

# Run the MCP server
CMD ["python", "mcp_server.py"]