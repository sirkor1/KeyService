# Один Dockerfile на три процесса.
#
# api, worker и bot собираются из одного дерева и различаются ровно точкой
# входа. Три почти одинаковых файла разошлись бы на первой же правке базового
# образа, а расхождение версии рантайма между процессами одного сервиса
# ищется долго.
#
# Какой проект собирать, задаётся аргументом сборки:
#   docker build --build-arg PROJECT=AmneziaKeyService.Worker .
# В docker-compose.yml это делает секция build.args каждого сервиса.
ARG PROJECT=AmneziaKeyService.Api

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG PROJECT
WORKDIR /src

# Сначала только csproj: слой restore переиспользуется, пока не менялись
# зависимости, и правка кода не тянет за собой повторную загрузку пакетов.
COPY ["src/AmneziaKeyService.Core/AmneziaKeyService.Core.csproj",                     "AmneziaKeyService.Core/"]
COPY ["src/AmneziaKeyService.Infrastructure/AmneziaKeyService.Infrastructure.csproj", "AmneziaKeyService.Infrastructure/"]
COPY ["src/AmneziaKeyService.Api/AmneziaKeyService.Api.csproj",                       "AmneziaKeyService.Api/"]
COPY ["src/AmneziaKeyService.Worker/AmneziaKeyService.Worker.csproj",                 "AmneziaKeyService.Worker/"]
COPY ["src/AmneziaKeyService.Bot/AmneziaKeyService.Bot.csproj",                       "AmneziaKeyService.Bot/"]

RUN dotnet restore "${PROJECT}/${PROJECT}.csproj"

COPY src/ ./

RUN dotnet publish "${PROJECT}/${PROJECT}.csproj" -c Release -o /app/publish --no-restore

# Образ aspnet для всех трёх: worker и bot обошлись бы runtime, но разные
# базовые образы в одном файле стоят дороже сэкономленных мегабайт.
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
ARG PROJECT
WORKDIR /app

COPY --from=build /app/publish .

# Слушает только api; для worker и bot переменная не значит ничего.
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

# Exec-форма ENTRYPOINT не разворачивает переменные, а имя сборки известно
# только на этапе сборки. sh -c с exec заменяет процесс оболочки собой,
# поэтому SIGTERM доходит до приложения и штатное завершение работает.
ENV APP_DLL=${PROJECT}.dll
ENTRYPOINT ["/bin/sh", "-c", "exec dotnet \"$APP_DLL\""]
