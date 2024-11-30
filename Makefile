local/setup:
	./gradlew clean build -xcheck

docker-up:
	docker compose up -d

docker-down:
	docker compose down

execute: docker-down local/setup docker-up