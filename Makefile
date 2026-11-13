.PHONY: setup test install clean

# 建环境：装锁定依赖（Python >= 3.11）
setup:
	python -m pip install pyyaml pytest

# 唯一的行为契约：本地与 CI 必须跑同一条命令
test:
	python -m pytest tests/ -v

install:
	python -c "print('hermes plugins install <本仓>/plugins/scope_gate  （装 Hermes 后执行）')"

clean:
	python -c "import pathlib,shutil; [shutil.rmtree(p) for p in pathlib.Path('.').rglob('__pycache__')]"
