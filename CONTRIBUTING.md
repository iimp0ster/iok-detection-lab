# Contributing to IOK Detection Lab

Thank you for considering contributing to IOK Detection Lab! This project benefits from community contributions.

## Ways to Contribute

### 1. Report Issues
- Bug reports
- Feature requests
- Documentation improvements
- Performance issues

**Create an issue:** [GitHub Issues](https://github.com/YOUR_USERNAME/iok-detection-lab/issues)

### 2. Improve Documentation
- Fix typos
- Add examples
- Clarify instructions
- Translate documentation

### 3. Write Custom IOK Rules
- Share rules for new phishing kits
- Document your detection logic
- Submit via Pull Request

**Note:** IOK rules should also be contributed to the upstream [IOK project](https://github.com/phish-report/IOK).

### 4. Code Contributions
- Bug fixes
- New features
- Performance improvements
- Test coverage

## Development Setup

```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/YOUR_USERNAME/iok-detection-lab.git
cd iok-detection-lab

# Create feature branch
git checkout -b feature/amazing-feature

# Run setup
./setup.sh
source venv/bin/activate

# Make your changes
# Test your changes

# Commit
git add .
git commit -m "Add amazing feature"

# Push to your fork
git push origin feature/amazing-feature

# Open Pull Request on GitHub
```

## Pull Request Process

1. **Fork** the repository
2. **Create branch** from `main`
3. **Make changes** with clear commits
4. **Test** your changes
5. **Update documentation** if needed
6. **Submit PR** with description of changes

### PR Guidelines

- One feature/fix per PR
- Clear commit messages
- Update README if adding features
- Test that setup.sh still works
- Follow existing code style

## Code Style

### Python
- Follow PEP 8
- Use meaningful variable names
- Add docstrings to functions
- Keep functions focused and short

### Documentation
- Use Markdown formatting
- Add code examples
- Keep line length reasonable
- Use proper headings

## Testing Your Changes

Before submitting PR:

```bash
# Test setup script
./setup.sh

# Test collector
python3 scripts/iok_collector.py https://example.com test.json

# Test detector
python3 scripts/iok_detector.py test.json IOK/indicators/

# Test API (if changed)
python3 siem-integration/iok_api.py
# In another terminal:
curl http://localhost:5000/health
```

## Custom IOK Rules

When contributing rules:

### Rule Format
```yaml
title: Clear Description of Detection
id: unique-uuid-v4
status: experimental  # or stable, deprecated
description: Detailed explanation
author: Your Name
date: YYYY-MM-DD
tags:
  - relevant-tag1
  - relevant-tag2
detection:
  selection:
    field|contains: 'pattern'
  condition: selection
level: high  # critical, high, medium, low
references:
  - https://link-to-analysis
```

### Rule Guidelines
- Use descriptive titles
- Add clear descriptions
- Include analysis links
- Tag appropriately
- Test against multiple samples
- Avoid false positives

### Testing Rules
```bash
# Create rule file
nano IOK/indicators/custom/my-rule.yml

# Test against collected samples
python3 scripts/iok_detector.py sample.json IOK/indicators/

# Verify it triggers correctly
```

## Documentation Contributions

### Adding Documentation
- Place in `docs/` directory
- Use `.md` extension
- Add to README if major guide
- Update index if needed

### Documentation Style
- Use clear, simple language
- Add code examples
- Include screenshots if helpful
- Use consistent formatting

## Reporting Security Issues

**Do not** open public issues for security vulnerabilities.

Instead:
1. Email: [Your Security Email]
2. Describe the issue
3. Include reproduction steps
4. Allow time for fix before disclosure

## Code of Conduct

### Our Standards
- Be respectful and professional
- Welcome newcomers
- Accept constructive criticism
- Focus on what's best for the community

### Unacceptable Behavior
- Harassment or discrimination
- Trolling or insulting comments
- Publishing others' private information
- Other unprofessional conduct

## Questions?

- **General questions:** Open a [GitHub Discussion](https://github.com/YOUR_USERNAME/iok-detection-lab/discussions)
- **Bug reports:** Open an [Issue](https://github.com/YOUR_USERNAME/iok-detection-lab/issues)
- **Security issues:** Email [your-email]

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Recognition

Contributors will be recognized in:
- README.md (Contributors section)
- Release notes
- GitHub contributor graphs

## Thank You!

Every contribution helps improve detection capabilities for the security community.

---

**First time contributing to open source?** 

Check out:
- [How to Contribute to Open Source](https://opensource.guide/how-to-contribute/)
- [GitHub's Guide to Contributing](https://docs.github.com/en/get-started/quickstart/contributing-to-projects)
