### Setup initial database

dotnet ef database update

### Database add migration

dotnet ef migrations add MyNewChange

### appsettings files

Serve as a template/documentation of what configuration values your application needs. Provide default values that work for basic development, and it’s great for non-sensitive configuration that:

- Doesn’t change between environments
- Safe to commit to source control (git)
- Is needed for the application to start

When developing without Dokcer and runs the application directly, these files are needed. They can also provide a fallback if the environment variables aren’t set.

### Reminder

When developing locally, put back the docker-compose files to repo.
