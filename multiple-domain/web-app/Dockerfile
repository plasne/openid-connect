FROM mcr.microsoft.com/dotnet/core/aspnet:3.1
WORKDIR /app
COPY out/ .
COPY wwwroot/ .
ENTRYPOINT ["dotnet", "web-plasne.dll"]