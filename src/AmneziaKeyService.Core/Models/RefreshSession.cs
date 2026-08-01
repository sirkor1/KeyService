using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AmneziaKeyService.Core.Models;

/// <summary>One-time refresh token record. Raw tokens never enter this model or MongoDB.</summary>
public class RefreshSession
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = default!;

    [BsonElement("userId")]
    public string UserId { get; set; } = default!;

    [BsonElement("familyId")]
    public string FamilyId { get; set; } = default!;

    [BsonElement("tokenHash")]
    public string TokenHash { get; set; } = default!;

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [BsonElement("expiresAt")]
    public DateTime ExpiresAt { get; set; }

    /// <summary>Set only after the parent token was atomically consumed.</summary>
    [BsonElement("activatedAt")]
    [BsonIgnoreIfNull]
    public DateTime? ActivatedAt { get; set; }

    [BsonElement("rotatedAt")]
    [BsonIgnoreIfNull]
    public DateTime? RotatedAt { get; set; }

    [BsonElement("replacedById")]
    [BsonIgnoreIfNull]
    public string? ReplacedById { get; set; }

    [BsonElement("revokedAt")]
    [BsonIgnoreIfNull]
    public DateTime? RevokedAt { get; set; }

    [BsonElement("revocationReason")]
    [BsonIgnoreIfNull]
    public string? RevocationReason { get; set; }
}

public enum RefreshRotationResult { Rotated, ReuseDetected, Invalid }
