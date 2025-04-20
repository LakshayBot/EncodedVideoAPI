using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EncodedVideoProject.Migrations
{
    /// <inheritdoc />
    public partial class AddUserSchemaAndRelation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "EncryptionKeys",
                columns: table => new
                {
                    Id = table.Column<string>(type: "text", nullable: false),
                    Algorithm = table.Column<string>(type: "text", nullable: false),
                    HashedKey = table.Column<string>(type: "text", nullable: false),
                    Salt = table.Column<string>(type: "text", nullable: true),
                    IV = table.Column<string>(type: "text", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EncryptionKeys", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Username = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Email = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    PasswordHash = table.Column<string>(type: "text", nullable: false),
                    FirstName = table.Column<string>(type: "text", nullable: true),
                    LastName = table.Column<string>(type: "text", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastLoginAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "EncryptedFiles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    FileName = table.Column<string>(type: "text", nullable: false),
                    ContentType = table.Column<string>(type: "text", nullable: false),
                    FileSize = table.Column<long>(type: "bigint", nullable: false),
                    FileContent = table.Column<byte[]>(type: "bytea", nullable: true),
                    FilePath = table.Column<string>(type: "text", nullable: true),
                    KeyId = table.Column<string>(type: "text", nullable: false),
                    IVId = table.Column<string>(type: "text", nullable: true),
                    Algorithm = table.Column<string>(type: "text", nullable: false),
                    VideoWidth = table.Column<int>(type: "integer", nullable: true),
                    VideoHeight = table.Column<int>(type: "integer", nullable: true),
                    VideoDuration = table.Column<double>(type: "double precision", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    ModifiedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    UserId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EncryptedFiles", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EncryptedFiles_EncryptionKeys_KeyId",
                        column: x => x.KeyId,
                        principalTable: "EncryptionKeys",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_EncryptedFiles_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateIndex(
                name: "IX_EncryptedFiles_KeyId",
                table: "EncryptedFiles",
                column: "KeyId");

            migrationBuilder.CreateIndex(
                name: "IX_EncryptedFiles_UserId",
                table: "EncryptedFiles",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Email",
                table: "Users",
                column: "Email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_Username",
                table: "Users",
                column: "Username",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "EncryptedFiles");

            migrationBuilder.DropTable(
                name: "EncryptionKeys");

            migrationBuilder.DropTable(
                name: "Users");
        }
    }
}
