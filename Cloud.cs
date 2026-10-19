using System.Security.Cryptography;
using System.Text;
using Npgsql;

// Cloud mode: har user ka apna account, apna data. PC control is version mein band hai.
static class Cloud
{
    public static bool Enabled;

    public static readonly HashSet<string> PcTools = new()
    {
        "open_app", "open_url", "play_youtube", "web_search", "type_text", "send_keys",
        "move_mouse", "click", "look_at_screen", "click_on", "wait", "volume", "media",
        "close_app", "lock_pc", "shutdown_pc", "cancel_shutdown", "read_code"
    };

    public const string Hint = """


        CLOUD MODE:
        - There is NO PC control in this version. If the user asks to control a PC or computer, say politely that PC control is not available yet.
        - You can use the phone_* tools and the personal tools (reminders, tasks, notes, expenses, habits, mood).
        """;
}

static class CurrentUser
{
    public static readonly AsyncLocal<Guid?> Id = new();
}

static class Auth
{
    const int Iter = 150_000;

    static NpgsqlConnection Plain(IConfiguration cfg) => new(cfg.GetConnectionString("Supabase"));

    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var h = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iter, HashAlgorithmName.SHA256, 32);
        return $"v1.{Iter}.{Convert.ToBase64String(salt)}.{Convert.ToBase64String(h)}";
    }

    static bool Verify(string password, string stored)
    {
        var p = stored.Split('.');
        if (p.Length != 4 || p[0] != "v1" || !int.TryParse(p[1], out var iter)) return false;
        var salt = Convert.FromBase64String(p[2]);
        var want = Convert.FromBase64String(p[3]);
        var got = Rfc2898DeriveBytes.Pbkdf2(password, salt, iter, HashAlgorithmName.SHA256, want.Length);
        return CryptographicOperations.FixedTimeEquals(got, want);
    }

    public static async Task<Guid?> CreateUser(IConfiguration cfg, string email, string password)
    {
        await using var conn = Plain(cfg);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            "insert into app_users (email, pass_hash) values (@e, @h) on conflict (email) do nothing returning id", conn);
        cmd.Parameters.AddWithValue("e", email);
        cmd.Parameters.AddWithValue("h", Hash(password));
        var r = await cmd.ExecuteScalarAsync();
        return r is Guid g ? g : null;
    }

    public static async Task<Guid?> CheckLogin(IConfiguration cfg, string email, string password)
    {
        await using var conn = Plain(cfg);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand("select id, pass_hash from app_users where email = @e", conn);
        cmd.Parameters.AddWithValue("e", email);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync())
        {
            Verify(password, "v1." + Iter + "." + Convert.ToBase64String(new byte[16]) + "." + Convert.ToBase64String(new byte[32])); // timing barabar rakhne ke liye
            return null;
        }
        return Verify(password, r.GetString(1)) ? r.GetGuid(0) : null;
    }

    // Token: userId.expiryUnix.signature (30 din)
    public static string MakeToken(Guid id, string secret)
    {
        var exp = DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds();
        var payload = $"{id:N}.{exp}";
        return payload + "." + Sign(payload, secret);
    }

    public static Guid? ReadToken(string token, string? secret)
    {
        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(secret) || secret.Length < 24) return null;
        var p = token.Split('.');
        if (p.Length != 3) return null;
        var payload = p[0] + "." + p[1];
        var good = Sign(payload, secret);
        if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(good), Encoding.UTF8.GetBytes(p[2]))) return null;
        if (!long.TryParse(p[1], out var exp) || DateTimeOffset.UtcNow.ToUnixTimeSeconds() > exp) return null;
        return Guid.TryParseExact(p[0], "N", out var id) ? id : null;
    }

    static string Sign(string payload, string secret)
    {
        using var h = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Convert.ToBase64String(h.ComputeHash(Encoding.UTF8.GetBytes(payload))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
