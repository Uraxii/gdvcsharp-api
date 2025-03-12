FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build-env
WORKDIR /src
COPY src .

#RUN ls -al
#RUN pwd

RUN dotnet restore
RUN dotnet publish -c Release -o build

FROM mcr.microsoft.com/dotnet/aspnet:9.0
WORKDIR /app
COPY --from=build-env /src/build ./
COPY --from=build-env /src/static ./static
EXPOSE 5001
ENTRYPOINT ["dotnet", "gdvcsharp-api.dll", "--urls", "http://0.0.0.0:5001"]
