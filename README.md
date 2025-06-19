# ogani-master

A modern fruit e-commerce website built with **ASP.NET Core MVC** (.NET 8), featuring a full shopping experience, admin management, MoMo payment integration, and more.

## Features

- User authentication and authorization
- Product catalog and search
- Shopping cart and checkout
- Order management (CRUD)
- MoMo payment gateway integration
- Email notifications (account creation, password reset, order updates)
- Admin dashboard for managing products, orders, banners, and blogs
- Responsive UI with modern design
- Rich text editing for admin content
- DataTables for advanced table features in admin
- Session management and security best practices

## Technologies Used

### Backend

- **.NET 8 (ASP.NET Core MVC)**
- **Entity Framework Core 9** (with SQL Server)
- **BCrypt.Net-Next** (password hashing)
- **DotNetEnv** (environment variable management)
- **X.PagedList** (pagination)
- **Microsoft.Extensions.Logging** (logging)
- **MoMo Payment Gateway** (integration)

### Frontend

- **Bootstrap 4** (UI framework)
- **jQuery** (DOM manipulation, AJAX)
- **jQuery UI** (UI widgets)
- **Owl Carousel** (responsive carousels)
- **Nice Select** (custom select boxes)
- **SlickNav** (responsive navigation)
- **Font Awesome** (icon set)
- **Bootstrap Icons** (icon set)
- **CKEditor 5** (rich text editor for admin)
- **OverlayScrollbars** (custom scrollbars)
- **DataTables** (advanced tables in admin)
- **Chart.js** (charts and analytics)
- **Paper Dashboard** (admin dashboard theme)
- **Custom CSS/JS** (site-specific styles and scripts)

### Other

- **Session-based authentication**
- **JWT configuration for API security**
- **Docker support** (if Dockerfile is present)
- **User secrets for local development**

## Getting Started

### Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [SQL Server](https://www.microsoft.com/en-us/sql-server/sql-server-downloads) (or Azure SQL)
- Node.js (for frontend asset management, if needed)
- (Optional) Docker

### Setup

1. **Clone the repository:**
   ```bash
   git clone <repo-url>
   cd ogani-master/ogani-master
   ```

2. **Configure the database:**
   - Update the `DefaultConnection` string in `appsettings.json` or `appsettings.Development.json` with your SQL Server credentials.

3. **Set up environment variables (for secrets):**
   - Use [User Secrets](https://learn.microsoft.com/en-us/aspnet/core/security/app-secrets) for local development:
     ```bash
     dotnet user-secrets set "JWT_SECRET:Secret" "your-jwt-secret"
     dotnet user-secrets set "JWT_SECRET:Issuer" "your-app"
     dotnet user-secrets set "JWT_SECRET:Audience" "your-app"
     ```
   - Or edit the `appsettings.Development.json` directly (not recommended for production).

4. **Apply database migrations:**
   ```bash
   dotnet ef database update
   ```

5. **Run the application:**
   ```bash
   dotnet run
   ```
   The app will be available at `https://localhost:7173` or `http://localhost:5037` (see `Properties/launchSettings.json`).

6. **(Optional) Run with Docker:**
   If a `Dockerfile` is present:
   ```bash
   docker build -t ogani-master .
   docker run -p 8080:80 ogani-master
   ```

### Admin Area

- Access the admin dashboard at `/Admin`
- Default admin credentials can be set in the database or via seeding (see code for details)

### Configuration

- **Email:** Configure SMTP settings in `appsettings.json` if email features are used.
- **MoMo Payment:** Set up MoMo credentials in configuration files or environment variables.
- **Session:** Session timeout and cookie settings are configured in `Program.cs`.

### Project Structure

- `Controllers/` - MVC controllers for user-facing features
- `Areas/Admin/` - Admin area (controllers, views, models)
- `Models/` - Entity models
- `Views/` - Razor views
- `wwwroot/` - Static assets (CSS, JS, images, plugins)
- `dto/` - Data transfer objects
- `Middlewares/` - Custom middleware
- `Helpers/` - Utility classes

### Useful Scripts

- **Database migration:** `dotnet ef migrations add <MigrationName>`
- **Update database:** `dotnet ef database update`

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙋‍♂️ Support

This project is developed and maintained by a single developer.  
For support or inquiries, please contact me at: **phanhuynhvanan@gmail.com**
