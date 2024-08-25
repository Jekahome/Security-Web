.PHONY: all

# Определите цель all
all: commit

# Определите цель commit, чтобы делать коммит и пуш
commit:
	git add . && \
	git commit -m "Fmt" && \
	git push

# Определите цель clean для очищения потенциальных временных файлов (если это актуально)
clean:
	git clean -fd
