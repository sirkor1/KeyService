using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AmneziaKeyService.Core.Models;

public class PassCode
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = default!;

    [BsonElement("code")]
    public string Code { get; set; } = default!;

    [BsonElement("isUsed")]
    public bool IsUsed { get; set; } = false;

    /// <summary>Отозванный код остаётся в журнале, но больше не может быть использован.</summary>
    [BsonElement("isRevoked")]
    public bool IsRevoked { get; set; }

    [BsonElement("revokedAt")]
    public DateTime? RevokedAt { get; set; }

    [BsonElement("usedByUserId")]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? UsedByUserId { get; set; }

    [BsonElement("usedAt")]
    public DateTime? UsedAt { get; set; }

    /// <summary>Короткоживущий резерв регистрации. Не является фактом использования.</summary>
    [BsonElement("claimToken")]
    public string? ClaimToken { get; set; }

    [BsonElement("claimedAt")]
    public DateTime? ClaimedAt { get; set; }

    [BsonElement("claimUsername")]
    public string? ClaimUsername { get; set; }

    /// <summary>Хеш нужен только до завершения регистрации, чтобы тот же запрос мог безопасно продолжить её.</summary>
    [BsonElement("claimPasswordHash")]
    public string? ClaimPasswordHash { get; set; }

    [BsonElement("claimTelegramId")]
    public long? ClaimTelegramId { get; set; }

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
