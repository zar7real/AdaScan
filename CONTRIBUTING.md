# 🤝 Contributing to AdaScan

Thank you for your interest in contributing to AdaScan! We welcome contributions from the cybersecurity community and appreciate your help in making this tool better for everyone.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Submitting Changes](#submitting-changes)
- [Security Considerations](#security-considerations)
- [Community Guidelines](#community-guidelines)

## 🛡️ Code of Conduct

This project adheres to a code of conduct that ensures a welcoming and inclusive environment for all contributors. By participating, you agree to:

- **Be respectful** and considerate in all interactions
- **Be collaborative** and help others learn and grow
- **Be responsible** with security-related contributions
- **Follow ethical guidelines** for security tool development

### Prohibited Activities
- Sharing or discussing techniques for illegal activities
- Contributing code designed for malicious purposes
- Harassment or discrimination of any kind
- Violating responsible disclosure principles

## 🚀 Getting Started

### Prerequisites

Before contributing, ensure you have:

- **Python 3.6+** installed
- **Git** for version control
- **Basic understanding** of network security concepts
- **Familiarity** with Python development practices

### First Steps

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/zar7real/AdaScan.git
   cd AdaScan
   ```
3. **Set up the development environment** (see [Development Setup](#development-setup))
4. **Explore the codebase** and run the existing tests

## 🛠️ How to Contribute

### Types of Contributions We Welcome

#### 🐛 **Bug Reports**
- Clear description of the issue
- Steps to reproduce the problem
- Expected vs. actual behavior
- System information (OS, Python version, etc.)
- Log files or error messages

#### ✨ **Feature Requests**
- Clear description of the proposed feature
- Use case and benefits explanation
- Consideration of security implications
- Mockups or examples if applicable

#### 🔧 **Code Contributions**
- Bug fixes and improvements
- New scanning modules or techniques
- Performance optimizations
- Documentation improvements
- Test coverage enhancements

#### 📚 **Documentation**
- README improvements
- Code comments and docstrings
- Usage examples and tutorials
- Wiki contributions

### Areas We Need Help With

- **Scanner Modules**: New vulnerability detection techniques
- **Report Formats**: Additional output formats or visualizations
- **API Integrations**: Support for new vulnerability databases
- **Performance**: Optimization for large-scale scanning
- **Testing**: Comprehensive test coverage
- **Documentation**: User guides and technical documentation

## 💻 Development Setup

### Environment Setup

1. **Clone and navigate**:
   ```bash
   git clone https://github.com/zar7real/Adascan.git
   cd AdaScan
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   # or
   venv\Scripts\activate     # Windows
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # Development dependencies
   ```

4. **Install system dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install nmap
   
   # macOS
   brew install nmap
   
   # Windows - Download from https://nmap.org/download.html
   ```

### Development Dependencies

Create `requirements-dev.txt`:
```text
pytest>=6.0.0
pytest-cov>=2.10.0
flake8>=3.8.0
black>=21.0.0
mypy>=0.812
pre-commit>=2.15.0
```

### Pre-commit Hooks

Set up pre-commit hooks for code quality:

```bash
pip install pre-commit
pre-commit install
```

## 📝 Coding Standards

### Python Style Guide

We follow **PEP 8** with these specific guidelines:

#### Code Formatting
```bash
# Use Black for automatic formatting
black adascan.py

# Check with flake8
flake8 adascan.py --max-line-length=100
```

#### Naming Conventions
- **Classes**: `PascalCase` (e.g., `VulnerabilityScanner`)
- **Functions/Methods**: `snake_case` (e.g., `scan_device`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `DEFAULT_TIMEOUT`)
- **Variables**: `snake_case` (e.g., `device_list`)

#### Documentation Standards
```python
def scan_device(device: DeviceInfo, port_range: str) -> DeviceInfo:
    """
    Perform comprehensive scan of a network device.
    
    Args:
        device: DeviceInfo object containing target information
        port_range: String specifying ports to scan (e.g., "22,80,443")
    
    Returns:
        DeviceInfo: Updated device object with scan results
        
    Raises:
        ScanError: If scan fails due to network issues
        
    Example:
        >>> device = DeviceInfo(ip="192.168.1.1")
        >>> result = scan_device(device, "22,80,443")
        >>> print(len(result.services))
        3
    """
```

### Security-Specific Guidelines

#### Input Validation
```python
def validate_ip_range(ip_range: str) -> bool:
    """Validate IP range to prevent injection attacks."""
    # Always validate and sanitize user inputs
    pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    return bool(re.match(pattern, ip_range))
```

#### Error Handling
```python
try:
    result = api_call(target)
except requests.exceptions.RequestException as e:
    logger.error(f"API call failed: {e}")
    # Never expose sensitive information in error messages
    raise ScanError("Network request failed")
```

#### Logging Guidelines
```python
# Good - No sensitive information
logger.info(f"Scanning {len(targets)} targets")

# Bad - Exposes internal details
logger.info(f"Using API key: {api_key}")
```

## 🧪 Testing Guidelines

### Test Structure

```
tests/
├── unit/
│   ├── test_scanner.py
│   ├── test_device_info.py
│   └── test_utils.py
├── integration/
│   ├── test_api_integration.py
│   └── test_end_to_end.py
├── fixtures/
│   ├── sample_responses.json
│   └── test_config.json
└── conftest.py
```

### Writing Tests

#### Unit Tests
```python
import pytest
from adascan import VulnerabilityScanner, DeviceInfo

class TestVulnerabilityScanner:
    def test_device_discovery_single_ip(self):
        """Test device discovery for single IP address."""
        scanner = VulnerabilityScanner()
        devices = scanner.discover_devices("192.168.1.1")
        
        assert isinstance(devices, list)
        assert len(devices) >= 0
        
    def test_invalid_ip_range_handling(self):
        """Test handling of invalid IP ranges."""
        scanner = VulnerabilityScanner()
        
        with pytest.raises(ValueError):
            scanner.discover_devices("invalid-ip")
```

#### Integration Tests
```python
@pytest.mark.integration
def test_nvd_api_integration():
    """Test NVD API integration with real API calls."""
    # Use test API keys or mock responses
    pass
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=adascan --cov-report=html

# Run specific test categories
pytest -m "not integration"  # Skip integration tests
pytest tests/unit/           # Only unit tests
```

### Test Data Security

- **Never commit real API keys** or sensitive data
- **Use mock responses** for external API tests
- **Anonymize network data** in test fixtures
- **Use safe test targets** (localhost, test networks)

## 📤 Submitting Changes

### Pull Request Process

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/vulnerability-scanner-improvement
   ```

2. **Make your changes** following coding standards

3. **Add tests** for new functionality

4. **Update documentation** if needed

5. **Run the test suite**:
   ```bash
   pytest
   flake8 adascan.py
   black --check adascan.py
   ```

6. **Commit with clear messages**:
   ```bash
   git commit -m "feat: add CVE severity filtering to scanner
   
   - Implement CVSS score-based filtering
   - Add configuration option for minimum severity
   - Include tests for new filtering logic
   - Update documentation with examples"
   ```

7. **Push and create pull request**:
   ```bash
   git push origin feature/vulnerability-scanner-improvement
   ```

### Pull Request Template

```markdown
## Description
Brief description of changes and motivation.

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Security Considerations
- [ ] Changes have been reviewed for security implications
- [ ] No sensitive information is exposed in logs or output
- [ ] Input validation has been implemented where appropriate

## Testing
- [ ] Tests pass locally
- [ ] New tests have been added for new functionality
- [ ] Integration tests pass (if applicable)

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review of code completed
- [ ] Code is commented, particularly in hard-to-understand areas
- [ ] Documentation has been updated
- [ ] No new warnings introduced
```

### Commit Message Guidelines

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Formatting changes
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(scanner): add support for IPv6 scanning

fix(api): handle rate limiting errors gracefully

docs(readme): update installation instructions for Windows

test(integration): add tests for Shodan API integration
```

## 🔒 Security Considerations

### Responsible Development

- **Security First**: Always consider security implications of changes
- **Input Validation**: Validate and sanitize all user inputs
- **Error Handling**: Don't expose sensitive information in error messages
- **Logging**: Never log API keys, passwords, or sensitive data
- **Dependencies**: Keep dependencies updated and secure

### Security Review Process

All security-related contributions undergo additional review:

1. **Code Review**: Manual inspection by security-aware maintainers
2. **Testing**: Comprehensive testing including edge cases
3. **Documentation**: Clear documentation of security implications
4. **Responsible Disclosure**: Following responsible disclosure for any discovered vulnerabilities

### Reporting Security Issues

**DO NOT** create public issues for security vulnerabilities.

Instead, email: None

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

## 🌟 Recognition

### Contributors

We recognize contributors in several ways:

- **README Contributors Section**: All contributors listed
- **Release Notes**: Significant contributions highlighted
- **GitHub Discussions**: Community recognition posts
- **LinkedIn/Twitter**: Social media recognition (with permission)

### Types of Recognition

- 🥇 **Core Maintainer**: Regular, significant contributions
- 🥈 **Feature Contributor**: Major feature implementations
- 🥉 **Bug Hunter**: Significant bug fixes and testing
- 📚 **Documentation Hero**: Outstanding documentation contributions
- 🔒 **Security Researcher**: Security improvements and discoveries

## 💬 Community Guidelines

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and community discussion
- **Pull Requests**: Code review and collaboration
- **Email**: security@alchemydivision.com for security issues

### Getting Help

- **Documentation**: Check README and wiki first
- **Existing Issues**: Search for similar problems
- **Discussions**: Ask questions in GitHub Discussions
- **Code Review**: Request feedback on draft pull requests

### Community Values

- **Learning**: Help others learn and grow
- **Collaboration**: Work together toward common goals
- **Quality**: Strive for high-quality, secure code
- **Ethics**: Maintain ethical standards in security research
- **Inclusivity**: Welcome contributors from all backgrounds

## 📞 Contact

- **General Questions**: Create a GitHub Discussion
- **Bug Reports**: Create a GitHub Issue
- **Security Issues**: None
- **Feature Requests**: Create a GitHub Issue with the "enhancement" label

---

## 🙏 Thank You

Thank you for considering contributing to AdaScan! Your contributions help make the cybersecurity community stronger and more secure.

**Remember**: Every contribution, no matter how small, makes a difference. Whether it's fixing a typo, reporting a bug, or implementing a major feature, we appreciate your effort and dedication.

---

*This contributing guide is a living document. If you have suggestions for improvement, please submit a pull request or create an issue.*
