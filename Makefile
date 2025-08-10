NAME = transcendence

GREEN := \033[0;32m

YELLOW := \033[0;33m

RESET := \033[0m

all:
	mkdir -p requirements/friend/tools/data requirements/record/tools/data requirements/record/tools/data
	mkdir -p requirements/user/tools/data requirements/user/tools/avatar
	docker compose -f docker-compose.yml up -d --build
	clear

	@echo "$(GREEN)----------------------FT_TRANSCENDENCE-----------------------$(RESET)"
	@echo "$(GREEN)Pong game is running$(RESET)"
	@echo "$(GREEN)Local launch: https://localhost:9000$(RESET)"
	@echo "$(GREEN)Remote launch: https://server_ip:9000$(RESET)"
	@echo "$(GREEN)-------------------------------------------------------------$(RESET)"

$(NAME): all

start:
	docker compose -f docker-compose.yml up -d
	clear
	@echo "$(GREEN)----------------------FT_TRANSCENDENCE-----------------------$(RESET)"
	@echo "$(GREEN)Pong game is running$(RESET)"
	@echo "$(GREEN)Local launch: https://localhost:9000$(RESET)"
	@echo "$(GREEN)Remote launch: https://server_ip:9000$(RESET)"
	@echo "$(GREEN)-------------------------------------------------------------$(RESET)"

stop:
	docker compose -f docker-compose.yml stop

get-data:
	mkdir -p data data/user data/friend data/record
	@docker cp t_user:/app/transcendence/user_manage/data data/user || echo "Warning: failed to copy."
	@docker cp t_user:/app/transcendence/user_manage/avatar data/user || echo "Warning: failed to copy"
	@docker cp t_record:/app/transcendence/record_manage/data data/record || echo "Warning: failed to copy"
	@docker cp t_friend:/app/transcendence/friend_manage/data data/friend || echo "Warning: failed to copy"
	@echo "$(GREEN)--------------------------GET DATA-------------------------$(RESET)"

put-data:
	@mkdir -p requirements/user/tools/data
	@cp -r data/user/data/* requirements/user/tools/data/ || echo "Warning: failed to copy."

	@mkdir -p requirements/user/tools/avatar
	@cp -r data/user/avatar/* requirements/user/tools/avatar/ || echo "Warning: failed to copy."

	@mkdir -p requirements/friend/tools/data
	@cp -r data/friend/data/* requirements/friend/tools/data/ || echo "Warning: failed to copy."

	@mkdir -p requirements/record/tools/data
	@cp -r data/record/data/* requirements/record/tools/data/ || echo "Warning: failed to copy."
	@echo "$(GREEN)--------------------------PUT DATA--------------------------$(RESET)"

restore:
	@docker cp t_user:/app/transcendence/user_manage/data requirements/user/tools && docker cp t_user:/app/transcendence/user_manage/avatar requirements/user/tools || echo "Warning: failed to copy."
	@docker cp t_friend:/app/transcendence/friend_manage/data requirements/friend/tools || echo "Warning: failed to copy."
	@docker cp t_record:/app/transcendence/record_manage/data requirements/record/tools || echo "Warning: failed to copy."

re-restore: restore re
	@echo "$(GREEN)---------------------REBUILD WITH DATA-----------------------$(RESET)"

clean:
	make stop
	docker system prune -af

re: clean all

.PHONY: all start stop clean re get-data put-data restore re-restore


