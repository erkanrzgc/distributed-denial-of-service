# Contributing

We welcome contributions! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/erkanrzgc/distributed-denial-of-service.git
cd distributed-denial-of-service
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-asyncio
```

## Running Tests

```bash
# All tests
python3 -m pytest tests/ -v

# Specific test file
python3 -m pytest tests/test_defense.py -v

# With coverage
python3 -m pytest tests/ --cov=. --cov-report=term
```

## Code Style

- Python 3.11+ with type hints
- Follow PEP 8
- Use `structlog` for logging (no `print`)
- Keep modules under 300 lines where possible
- All public methods should have docstrings

## Adding a New Attack Module

1. Create `attack/your_attack.py`
2. Inherit from `BaseAttacker`
3. Implement `async def run(self, **kwargs)`
4. Set `name` and `description` class attributes
5. It auto-registers via `__init_subclass__`

```python
class MyAttack(BaseAttacker):
    name = "my_attack"
    description = "My custom attack"

    async def run(self, target: str, rate: int = 100, **kwargs):
        # Your attack logic here
        pass
```

## Adding a New Defense/Detection Module

Same pattern: inherit from `BaseDefender` or `BaseDetector`.

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Add tests for your changes
4. Ensure all tests pass (`python3 -m pytest tests/`)
5. Update documentation if needed
6. Submit a PR with a clear description

## Commit Convention

```
type: short description

feat: add DNS amplification module
fix: resolve rate limiter token leak
docs: update CLI usage examples
test: add WAF SQL injection tests
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

## Questions?

Open an issue or start a discussion.
