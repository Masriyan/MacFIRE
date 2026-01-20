# Contributing to MacFIRE

Thank you for your interest in contributing to MacFIRE! This document provides guidelines and instructions for contributing.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We expect all contributors to:

- Be respectful and constructive in discussions
- Welcome newcomers and help them learn
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/MacFIRE.git
   cd MacFIRE
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/Masriyan/MacFIRE.git
   ```

## Development Setup

### Prerequisites
- Python 3.8 or higher
- macOS Catalina (10.15) or later for testing
- Git

### Setup
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies (if any)
# pip install -r requirements-dev.txt

# Verify the tool works
python3 macfire.py --version
```

## Making Changes

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following our coding standards

3. **Test your changes**:
   ```bash
   # Syntax check
   python3 -m py_compile macfire.py
   
   # Basic functionality
   python3 macfire.py --help
   python3 macfire.py --list-categories
   ```

4. **Commit your changes**:
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   ```

## Pull Request Process

1. Update documentation if needed
2. Update CHANGELOG.md with your changes
3. Ensure all tests pass
4. Submit the pull request with a clear description

### Commit Message Format

Use conventional commits format:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `refactor:` Code refactoring
- `test:` Adding tests
- `chore:` Maintenance tasks

## Coding Standards

### Python Style
- Follow PEP 8 guidelines
- Use type hints for function parameters and returns
- Write docstrings for all functions and classes
- Maximum line length: 100 characters

### Code Structure
```python
def function_name(param: str, optional_param: int = 10) -> Dict[str, Any]:
    """
    Brief description of function.
    
    Args:
        param: Description of param
        optional_param: Description of optional param
    
    Returns:
        Description of return value
    """
    # Implementation
    pass
```

### Adding New Artifact Categories

To add a new artifact category, add an entry to the `ARTIFACTS` dictionary:

```python
ARTIFACTS["Category Name"] = {
    "description": "Brief description of what this collects",
    "priority": 2,  # 1=HIGH, 2=MEDIUM, 3=LOW
    "paths": [
        "/path/to/artifact",
        "~/Library/path/to/user/artifact"
    ],
    "commands": [
        "command > ./output.txt"
    ]
}
```

## Questions?

If you have questions, please open an issue on GitHub or contact the maintainers.

---

Thank you for contributing to MacFIRE! 🔥
