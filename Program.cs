using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;
using Microsoft.AspNetCore.Authorization;
using Swashbuckle.AspNetCore.SwaggerGen;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Api for Kerry Mini Project", Version = "v1" });

    // Add security definition for API key header
    c.AddSecurityDefinition("apiKey", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Name = "API-Key",  // The name of the request header with the API key
        Type = SecuritySchemeType.ApiKey,
        Scheme = "API-Key",
        Description = "API key needed to access the endpoints."
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "apiKey" },
            },
            new List<string>()
        }
    });

    // For each method that requires the apiKey header
    c.OperationFilter<AppendAuthorizeToSummaryOperationFilter>();  // This will append "(Auth)" to the summary of Operations that require Authorization
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}



app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();

public class AppendAuthorizeToSummaryOperationFilter : IOperationFilter
{
    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        var authAttributes = context.MethodInfo.DeclaringType.GetCustomAttributes(true)
            .Union(context.MethodInfo.GetCustomAttributes(true))
            .OfType<AuthorizeAttribute>();

        if (authAttributes.Any())
            operation.Summary += " (Auth)";  // Append "(Auth)" to the summary
    }
}

[AttributeUsage(AttributeTargets.Method)]
public class RequiresHeaderAttribute : Attribute
{
    public string[] Headers { get; set; }

    public RequiresHeaderAttribute(params string[] headers)
    {
        Headers = headers;
    }
}

public class AddRequiredHeaderParameter : IOperationFilter
{
    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        var requiresHeaderAttribute = context.MethodInfo.GetCustomAttributes(true)
            .SingleOrDefault(attribute => attribute is RequiresHeaderAttribute) as RequiresHeaderAttribute;

        if (requiresHeaderAttribute != null)
        {
            if (operation.Parameters == null)
                operation.Parameters = new List<OpenApiParameter>();

            foreach (var header in requiresHeaderAttribute.Headers)
            {
                // Check if this operation already has a parameter for this header
                if (!operation.Parameters.Any(p => p.Name == header))
                {
                    operation.Parameters.Add(new OpenApiParameter
                    {
                        Name = header,
                        In = ParameterLocation.Header,
                        Required = true, // Set to false if this header is not required
                        Schema = new OpenApiSchema { Type = "String" }
                    });
                }
            }
        }
    }
}
