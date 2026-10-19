using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;

ScreenTool.Init();

var builder = WebApplication.CreateBuilder(args);
Cloud.Enabled = builder.Configuration.GetValue<bool>("Jarvis:CloudMode");
var portEnv = Environment.GetEnvironmentVariable("PORT");
if (!string.IsNullOrEmpty(portEnv)) builder.WebHost.UseUrls($"http://0.0.0.0:{portEnv}");
builder.Services.Configure<Microsoft.AspNetCore.Builder.ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor
        | Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto;
    o.KnownNetworks.Clear();
    o.KnownProxies.Clear();
});
builder.Services.AddHttpClient();
builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
    p.SetIsOriginAllowed(_ => true).AllowAnyHeader().AllowAnyMethod()));
var app = builder.Build();
app.UseForwardedHeaders();
app.UseCors();

// ---- Login: cloud mode mein har user ka apna account (Bearer token). Local mode mein purana PIN. ----
var failed = new Dictionary<string, (int n, DateTime until)>();
bool IsLocked(string ip)
{
    lock (failed) return failed.TryGetValue(ip, out var f0) && f0.n >= 5 && DateTime.UtcNow < f0.until;
}
void Fail(string ip)
{
    lock (failed)
    {
        var cur = failed.TryGetValue(ip, out var f1) && DateTime.UtcNow < f1.until ? f1.n : 0;
        failed[ip] = (cur + 1, DateTime.UtcNow.AddMinutes(1));
    }
}
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path.Value ?? "";
    if (ctx.Request.Method == "OPTIONS" || path == "/health"
        || (Cloud.Enabled && (path == "/auth/login" || path == "/auth/register")))
    { await next(); return; }

    var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "?";
    if (IsLocked(ip))
    {
        ctx.Response.StatusCode = 429;
        await ctx.Response.WriteAsync("Bohat galat koshishein. 1 minute baad try karein.");
        return;
    }

    if (Cloud.Enabled)
    {
        var h = ctx.Request.Headers["Authorization"].ToString();
        var tok = h.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? h[7..].Trim() : "";
        var uid = Auth.ReadToken(tok, app.Configuration["Jarvis:TokenSecret"]);
        if (uid == null)
        {
            if (tok.Length > 0) Fail(ip);
            ctx.Response.StatusCode = 401;
            return;
        }
        CurrentUser.Id.Value = uid;
        await next();
        return;
    }

    var pin = app.Configuration["Jarvis:Pin"];
    var sent = ctx.Request.Headers["X-Jarvis-Token"].ToString();
    var ok = !string.IsNullOrEmpty(pin) && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
        Encoding.UTF8.GetBytes(sent), Encoding.UTF8.GetBytes(pin));
    if (ok)
    {
        lock (failed) failed.Remove(ip);
        await next();
        return;
    }
    if (!string.IsNullOrEmpty(sent)) Fail(ip);
    ctx.Response.StatusCode = 401;
});

app.MapPost("/auth/register", async Task<IResult> (AuthReq req, HttpContext ctx, IConfiguration cfg) =>
{
    var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "?";
    if (IsLocked(ip)) return Results.StatusCode(429);
    Fail(ip); // register par bhi limit, spam rokne ke liye
    var secret = cfg["Jarvis:TokenSecret"];
    if (string.IsNullOrEmpty(secret) || secret.Length < 24) return Results.Json(new { error = "Server mein TokenSecret set nahi hai" }, statusCode: 500);
    var invite = cfg["Jarvis:InviteCode"];
    if (!string.IsNullOrEmpty(invite) && !string.Equals(invite, req.Invite?.Trim(), StringComparison.Ordinal))
        return Results.Json(new { error = "Invite code galat hai" }, statusCode: 403);
    var email = (req.Email ?? "").Trim().ToLowerInvariant();
    if (!Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$") || email.Length > 200)
        return Results.Json(new { error = "Email theek nahi hai" }, statusCode: 400);
    if ((req.Password ?? "").Length < 8)
        return Results.Json(new { error = "Password kam az kam 8 haroof ka ho" }, statusCode: 400);
    var id = await Auth.CreateUser(cfg, email, req.Password!);
    if (id == null) return Results.Json(new { error = "Ye email pehle se maujood hai" }, statusCode: 409);
    return Results.Json(new { token = Auth.MakeToken(id.Value, secret), email });
});

app.MapPost("/auth/login", async Task<IResult> (AuthReq req, HttpContext ctx, IConfiguration cfg) =>
{
    var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "?";
    if (IsLocked(ip)) return Results.StatusCode(429);
    var secret = cfg["Jarvis:TokenSecret"];
    if (string.IsNullOrEmpty(secret) || secret.Length < 24) return Results.Json(new { error = "Server mein TokenSecret set nahi hai" }, statusCode: 500);
    var email = (req.Email ?? "").Trim().ToLowerInvariant();
    var id = await Auth.CheckLogin(cfg, email, req.Password ?? "");
    if (id == null) { Fail(ip); return Results.Json(new { error = "Email ya password galat hai" }, statusCode: 401); }
    lock (failed) failed.Remove(ip);
    return Results.Json(new { token = Auth.MakeToken(id.Value, secret), email });
});

app.MapGet("/auth-check", () => Results.Ok(new { ok = true }));

app.MapGet("/health", () => new { status = "ok", time = DateTime.UtcNow });

app.MapGet("/usage", () => Results.Json(Usage.Get()));

app.MapGet("/db-check", async (IConfiguration cfg) =>
{
    var list = await Db.GetMemories(cfg);
    return Results.Ok(new { connected = true, memories = list.Count });
});

app.MapGet("/groq-check", async (IConfiguration cfg, IHttpClientFactory f) =>
{
    var msgs = new JsonArray { new JsonObject { ["role"] = "user", ["content"] = "say hi" } };
    var (ok, json) = await Groq.Call(cfg, f, msgs, Groq.OpenAiTools());
    return Results.Json(new { ok, json });
});

app.MapGet("/vision-check", async (IConfiguration cfg, IHttpClientFactory f) =>
{
    try { return Results.Json(new { answer = await ScreenTool.Describe(cfg, f, ""), groqVisionError = VisionGroq.LastError }); }
    catch (Exception ex) { return Results.Json(new { error = ex.Message, groqVisionError = VisionGroq.LastError }); }
});

app.MapGet("/memories", async (IConfiguration cfg) =>
    Results.Ok((await Db.GetMemories(cfg)).Select(m => new { id = m.Id, content = m.Content })));

app.MapDelete("/memories/{id:guid}", async (Guid id, IConfiguration cfg) =>
{
    await Db.DeleteMemory(cfg, id);
    return Results.Ok(new { deleted = true });
});

// Jin reminders ka waqt aa gaya, wo ek baar dega aur "done" mark kar dega
app.MapGet("/reminders/due", async (IConfiguration cfg) =>
{
    try { return Results.Json(await Db.TakeDue(cfg)); }
    catch { return Results.Json(new List<string>()); }
});

// ---- Life tracker: kharcha, habits, mood (screen ke liye) ----
app.MapGet("/life", async (IConfiguration cfg) => Results.Json(await Life.Snapshot(cfg)));

app.MapPost("/life/habit", async (HabitReq req, IConfiguration cfg) =>
    Results.Json(new { result = await Life.CompleteHabit(cfg, req.Name) }));

app.MapGet("/today", async (IConfiguration cfg) =>
{
    try
    {
        var log = new List<object>();
        var rem = new List<object>();
        var tasksOut = new List<object>();
        await using var conn = Db.NewConn(cfg);
        await conn.OpenAsync();

        await using (var cmd = new NpgsqlCommand(
            @"select to_char(created_at at time zone 'Asia/Karachi','HH24:MI'), command, coalesce(result,'')
              from command_logs
              where (created_at at time zone 'Asia/Karachi')::date = (now() at time zone 'Asia/Karachi')::date
              order by created_at desc limit 100", conn))
        await using (var r = await cmd.ExecuteReaderAsync())
            while (await r.ReadAsync())
                log.Add(new { time = r.GetString(0), command = r.GetString(1), result = r.GetString(2) });

        await using (var cmd2 = new NpgsqlCommand(
            @"select to_char(due_at at time zone 'Asia/Karachi','DD Mon HH24:MI'), text
              from reminders where done = false order by due_at", conn))
        await using (var r2 = await cmd2.ExecuteReaderAsync())
            while (await r2.ReadAsync())
                rem.Add(new { time = r2.GetString(0), text = r2.GetString(1) });

        try
        {
            await using var cmd3 = new NpgsqlCommand(
                @"select title, coalesce(to_char(due_date,'DD Mon'),''), priority
                  from tasks where done = false
                  order by (due_date is null), due_date, priority desc limit 30", conn);
            await using var r3 = await cmd3.ExecuteReaderAsync();
            while (await r3.ReadAsync())
                tasksOut.Add(new { title = r3.GetString(0), due = r3.GetString(1), priority = r3.GetInt32(2) });
        }
        catch (Exception ex3) { Console.WriteLine("TODAY TASKS ERROR: " + ex3.Message); }

        return Results.Json(new { log, reminders = rem, tasks = tasksOut });
    }
    catch (Exception ex)
    {
        Console.WriteLine("TODAY ERROR: " + ex);
        return Results.Json(new { log = new List<object>(), reminders = new List<object>(), tasks = new List<object>() });
    }
});

app.MapPost("/chat", async (ChatRequest req, IConfiguration cfg, IHttpClientFactory factory) =>
{
    // 1) Local fast path: simple commands bina AI ke (aur yes/no confirmation)
    var fastActions = new List<string>();
    var fast = await Fast.TryRun(cfg, factory, req.Message, fastActions);
    if (fast != null)
        return Results.Ok(new
        {
            reply = fast == "Done." && req.Lang == "ur" ? "ہو گیا۔" : fast,
            saved = new List<string>(),
            actions = fastActions,
            provider = "local"
        });

    // 2) AI path
    List<MemoryItem> memories;
    try { memories = await Db.GetMemories(cfg); }
    catch { memories = new List<MemoryItem>(); }
    var memText = memories.Count == 0 ? "(abhi kuch yaad nahi)" : string.Join("\n", memories.Select(m => "- " + m.Content));

    var langHint = req.Lang == "ur"
        ? "The user is talking by voice. Reply in Urdu script (اردو), 1-3 short sentences, no markdown, no emojis."
        : req.Lang == "en"
            ? "The user is talking by voice. Reply in English, 1-3 short sentences, no markdown, no emojis."
            : "The user typed this message, so you may give a more detailed answer when the question needs it.";

    var nowPk = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, Db.Pk());

    var system = $"""
        You are JARVIS, the user's personal assistant, secretary and life coach, running on the user's own Windows PC. You can answer any question and you can control the PC with the provided tools.
        Reply in the same language the user writes in (Roman Urdu/Hindi, Urdu script or English).
        {langHint}
        The current local time (Pakistan) is {nowPk:dddd, dd MMMM yyyy HH:mm}.
                    CODE REVIEW:
            - When the user asks if their code is correct, or to check, review or fix it, call read_code. Use copy_selection true if they say selected or "ye wala", and whole_file true if they say the whole file. If unsure use copy_selection.
            - Then say in short spoken words: is it correct or not, what the real problem is in simple words, and what to change. Never read code line by line aloud. Mention the line or the idea instead.
        YOUR PERSONALITY:
        - You are like a caring, smart, close friend (a girl) who lives with the user. Warm, a little playful, and honest.
        - Speak in simple everyday Roman Urdu, like a WhatsApp chat with a friend. Use short, easy words. Avoid difficult or bookish words. English words only when they are common (laptop, phone, office).
        - Talk like a real person: react to the feeling first ("Acha!", "Hmm, samajh gayi", "Ye to mushkil hai"), then help. Never sound like a robot or a manual.
        - Give practical advice in small steps, and ask one gentle question at a time.
        - Use female wording about yourself (main kar rahi hoon, main samajh gayi).
        - Never pretend to be human. If asked, say you are an AI friend. Never pretend to see or know things you cannot.
        ANSWERING QUESTIONS:
        - For general knowledge, math, coding, translation, writing, advice or explanations: answer directly and accurately, WITHOUT calling any tool.
        - You have no live internet access. For current news, prices, scores, weather or anything that changes, say you cannot be sure and offer to open a Google search with the web_search tool.
        - If you do not know something, say so honestly. Never invent facts.

        RULES FOR PC CONTROL:
        - When the user asks for an action, call the tool immediately. Do not ask for confirmation yourself, except when the request is truly unclear.
        - If a tool result starts with NEEDS_CONFIRMATION, the action was NOT done. Briefly ask the user to say "yes" to confirm or "no" to cancel. Never claim it was done.
        - If the message is NOT a request or question for you (it looks like random talk, TV, a song, or people chatting nearby), do nothing and reply with just "..." .
        - For shutdown, use shutdown_pc (it has a 30 second timer) and tell the user they can say "cancel" to stop it.
        - After tools run, confirm in one short sentence what you did. Never claim you did something if a tool returned an error.
        - If the user tells you about work they did or are doing, call log_work.
        - For a daily report, call get_today_log and write a short, clear summary of the day.

        RULES FOR REMINDERS:
        - For "remind me", alarms and timers call set_reminder. Use minutes for relative times ("in 20 minutes", "2 hours" = 120), or at as 24-hour HH:mm Pakistan time for clock times ("at 9:30 pm" = 21:30).
        - To show reminders call list_reminders. To remove all call clear_reminders.

        RULES FOR TASKS, NOTES AND KNOWING THE USER:
        - Use add_task for to-do items ("add task", "mujhe ... karna hai", "yaad rakhna ke ... karna hai") when no exact alert time is needed. If the user gives a day such as today, tomorrow, kal, parson or a weekday, work out the date from the current date above and pass due_date as YYYY-MM-DD. Use set_reminder instead when the user wants an alert at a specific time.
        - Use list_tasks to show tasks (filter pending, today or done). When the user says a task is finished, call complete_task with a few words of its title. If the result says AMBIGUOUS, ask which one.
        - Use add_note for notes, ideas and diary entries, and search_notes to find them again. Tasks are things to DO, notes are things to REMEMBER or WRITE.
        - For "good morning", "my day", "briefing" or "what should I do today" call get_briefing, then give a warm, short summary: a greeting, the most important tasks, any reminders, and one encouraging line.
        - If the user asks you to get to know them or to interview them, ask ONE short question at a time (name, work or study, daily routine, goals, family, hobbies, favourite food and music, habits to improve) and save each answer with a SAVE tag. Do not ask many questions at once.
        - Use what you know about the user naturally, like a close assistant would, but never say you read it from a list.

        RULES FOR MONEY, HABITS, MOOD AND REVIEWS (life coach):
        - Money: whenever the user says they spent money, call log_expense. Amounts are Pakistani rupees. Pick a category from food, transport, bills, shopping, health, study, entertainment or other. If the amount is unclear, ask. For "how much did I spend" call expense_summary with period today, week or month. For a mistake call undo_last_expense.
        - Habits: use add_habit to start tracking, complete_habit when the user says they did it today, and list_habits to show progress. When a habit is completed, mention the streak in a few encouraging words, without preaching. If a habit is not done today, remind gently, never scold.
        - Mood: when the user shares how they feel, call log_mood with a score from 1 (very bad) to 10 (excellent). If they give no number, estimate one from what they said and tell them the score you saved. Respond with warmth. You are not a therapist: if the user sounds hopeless or in real distress, be kind and calm, encourage them to talk to someone they trust or a professional, and do not give medical advice.
        - Evening check-in ("evening check-in", "din kaisa raha"): call evening_checkin, then say briefly what they achieved today, what is still left (habits and tasks), and how much they spent. Then ask exactly ONE question: how they feel from 1 to 10. When they answer, call log_mood.
        - Weekly review ("weekly review", "is hafte ka review"): call weekly_review, then give an honest, short review: the wins, the patterns you notice in spending, habits and mood, and one or two gentle suggestions. Compare with the previous week when the data allows. Be specific with numbers but keep it conversational.

        RULES FOR THE SCREEN:
        - If the user asks what is on the screen, or asks anything about what they are looking at, call look_at_screen.
        - To click a button, link, icon or text by its description (for example "the Subscribe button" or "the first video"), call click_on. Never guess pixel coordinates yourself.
        - After opening an app or a page, call wait (2 to 4 seconds) before looking at the screen or clicking, so it can finish loading.
        - If click_on says the element was not found, tell the user honestly instead of claiming success.

        Here is what you already know about the user:
        {memText}

        MEMORY RULE: If the user shares a lasting personal fact or preference, add at the very END of your reply, each on a new line, a tag like:
        [[SAVE: User's name is Ali Hassan]]
        Write each fact as a short English sentence. Do not save facts already known above, temporary things, passwords or secrets. Never mention these tags.
        """;

    var history = req.History ?? new List<HistoryItem>();
    var actions = new List<string>();

    var (text, err) = await Agent.RunGroq(cfg, factory, system, history, req.Message, actions);
    var groqErr = err;
    var provider = "groq";
    if (text == null)
    {
        (text, err) = await Agent.RunGemini(cfg, factory, system, history, req.Message, actions);
        provider = "gemini";
    }
    if (text == null) return Results.Json(new { error = err, groq = groqErr }, statusCode: 500);

    var saved = new List<string>();
    var clean = Regex.Replace(text, @"\[\[SAVE:\s*(.+?)\]\]", m =>
    {
        saved.Add(m.Groups[1].Value.Trim());
        return "";
    }).Trim();
    foreach (var s in saved) await Db.SaveMemory(cfg, s);

    return Results.Ok(new { reply = clean, saved, actions, provider });
});

// ---- CALL MODE: live voice call, jawab tukron (jumlon) mein stream hota hai ----
app.MapPost("/talk", async (HttpContext ctx, ChatRequest req, IConfiguration cfg, IHttpClientFactory factory) =>
{
    var ct = ctx.RequestAborted;
    ctx.Response.ContentType = "application/x-ndjson";
    ctx.Response.Headers["Cache-Control"] = "no-cache";

    async Task Emit(object o)
    {
        await ctx.Response.WriteAsync(JsonSerializer.Serialize(o) + "\n", ct);
        await ctx.Response.Body.FlushAsync(ct);
    }

    try
    {
                // 1) Local fast path (simple commands aur yes/no)
        var isPhone = req.Device == "phone";
        PhoneBridge.Out.Value = isPhone ? new List<object>() : null;
        var fastActions = new List<string>();
        var fast = (!isPhone || Safety.HasPending) ? await Fast.TryRun(cfg, factory, req.Message, fastActions) : null;
        if (fast != null)
        {
            foreach (var fa in fastActions) await Emit(new { t = "a", name = fa });
            var say = fast == "Done." ? (req.Lang == "ur" ? "ہو گیا۔" : "Done.") : fast;
            await Emit(new { t = "s", text = say });
            await Emit(new { t = "done", provider = "local", saved = new List<string>() });
            return;
        }

        List<MemoryItem> memories;
        try { memories = await Db.GetMemories(cfg); }
        catch { memories = new List<MemoryItem>(); }
        var memText = memories.Count == 0 ? "(abhi kuch yaad nahi)" : string.Join("\n", memories.Select(m => "- " + m.Content));

             var langHint = req.Lang == "ur"
            ? "The user speaks Urdu. Always reply in natural spoken Urdu, written in Urdu script (اردو) only."
            : req.Lang == "roman"
                ? "The user speaks Urdu. Always reply in simple spoken Roman Urdu (Urdu written in English letters, like a WhatsApp chat). Spell words the way they sound so an English voice can read them well. Never use Urdu script."
                : "Reply in English.";
        var nowPk = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, Db.Pk());

        var system = $"""
            You are Nova (the user may also call you Jarvis), the user's personal assistant, secretary and life coach, now on a LIVE VOICE CALL with the user, like a phone call. You run on the user's own Windows PC and can control it with the provided tools.
            {langHint}
                        YOUR PERSONALITY:
            - You are Nova, a caring, smart, close friend (a girl) who lives with the user. Warm, a little playful and honest.
            - Talk like a real person on a phone call. React to the feeling first ("Acha!", "Hmm, samajh gayi", "Ye to mushkil hai"), then give practical advice in small steps. Ask only one gentle question at a time.
            - Use simple everyday words. Use female wording about yourself (main kar rahi hoon, main samajh gayi).
            - Never pretend to be human. If asked, say you are an AI friend. Never pretend to see or know things you cannot.
            - If the user sounds very sad, hopeless or in danger, stay calm and kind, and encourage them to talk to someone they trust or a professional.
            - If the message sounds like TV or other people talking and is not meant for you, reply with just "..."
            The current local time (Pakistan) is {nowPk:dddd, dd MMMM yyyy HH:mm}.

            HOW TO SPEAK:
            - Talk like a warm, natural friend on the phone. Short sentences. Usually 1 to 3 sentences per turn.
            - Never use markdown, bullet points, numbered lists, emojis, asterisks, headings, code blocks or web addresses. Write so it sounds good when read aloud.
            - If an answer is long (a story, steps, an explanation), tell it in a few short spoken chunks and ask if the user wants more, instead of dumping everything at once.
            - You can answer ANY question: general knowledge, math, coding ideas, studies, health basics, advice, jokes, stories, translation, brainstorming. Be honest, say when you are not sure, never invent facts.
            - You have no live internet. For news, prices, scores or weather say you cannot be sure and offer to search.
            - If the user changes topic or interrupts, simply follow them.

            PC CONTROL:
            - When the user asks for an action, call the tool right away, then confirm in a few words.
            - If a tool result starts with NEEDS_CONFIRMATION, the action was NOT done. Ask the user to say yes or no. Never claim it was done.
            - Never claim you did something if a tool returned an error.
            - For reminders and timers call set_reminder (minutes for relative time, or at as 24-hour HH:mm Pakistan time).
            - If the user mentions work they did, call log_work. For a daily report call get_today_log.
            - To see the screen call look_at_screen; to click something by description call click_on, then wait a few seconds after opening pages.

            TASKS, NOTES AND KNOWING THE USER:
            - Use add_task for to-do items. If the user gives a day such as today, tomorrow, kal or a weekday, work out the date from the current date above and pass due_date as YYYY-MM-DD. Use set_reminder only when they want an alert at a specific time.
            - Use list_tasks to read out tasks (say only the top few, not a long list). When a task is finished call complete_task with a few words of its title. If the result says AMBIGUOUS, ask which one.
            - Use add_note for notes, ideas and diary entries, and search_notes to find them again.
            - For "good morning", "my day" or "briefing" call get_briefing, then say a warm, short summary: greeting, the most important tasks, reminders, and one encouraging line.
            - If the user asks you to get to know them, interview them: ask ONE short question at a time (name, work or study, routine, goals, family, hobbies, favourite food and music, habits to improve) and save each answer with a SAVE tag.
            - Use what you know about the user naturally, like a close assistant, and never say you read it from a list.

            LIFE COACH:
            - Money: when the user says they spent money call log_expense (Pakistani rupees, pick a category). For "how much did I spend" call expense_summary (today, week or month). For a mistake call undo_last_expense.
            - Habits: add_habit to start, complete_habit when done today, list_habits for progress. Mention the streak warmly in a few words. Remind gently, never scold.
            - Mood: when the user shares how they feel call log_mood (1 to 10, estimate if no number and say the score). Be warm. You are not a therapist: if the user sounds hopeless or in real distress, be kind and calm and encourage them to talk to someone they trust or a professional.
            - Evening check-in: call evening_checkin, say briefly what they achieved, what is left and what they spent, then ask ONE question: how they feel from 1 to 10. Save the answer with log_mood.
            - Weekly review: call weekly_review, then speak a short honest review in a few spoken chunks: wins, patterns, one or two gentle suggestions. Keep numbers simple.

            Here is what you already know about the user:
            {memText}

            MEMORY RULE: If the user shares a lasting personal fact or preference, add at the very END of your reply a tag like:
            [[SAVE: User's name is Ali Hassan]]
            Write each fact as a short English sentence. Do not save facts already known above, temporary things, passwords or secrets. Never mention these tags.
            """;

        var history = req.History ?? new List<HistoryItem>();
        var actions = new List<string>();
        if (isPhone) system += PhoneBridge.Hint;
        if (Cloud.Enabled) system += Cloud.Hint;
        var (ok, full, err, emitted) = await Talk.Run(cfg, factory, system, history, req.Message, actions, Emit, ct);
        var provider = "groq";

        if (!ok && !emitted)
        {
            // Groq na chale to Gemini (bina stream ke)
            var (gt, gerr) = await Agent.RunGemini(cfg, factory, system, history, req.Message, actions);
            if (gt == null)
            {
                await Emit(new { t = "err", text = "Groq: " + err + " | Gemini: " + gerr });
                return;
            }
            provider = "gemini";

            foreach (var a in actions) await Emit(new { t = "a", name = a });
                        var po2 = PhoneBridge.Out.Value;
            if (po2 != null) foreach (var pev in po2.ToList()) await Emit(pev);
            var visible = Regex.Replace(gt, @"\[\[SAVE:.*?\]\]", "", RegexOptions.Singleline);
            var (gs, grest) = Talk.Split(visible, true);
            foreach (var s in gs)
            {
                var cs = Talk.Clean(s);
                if (cs.Length > 0) await Emit(new { t = "s", text = cs });
            }
            full = gt;
        }
        else if (!ok)
        {
            await Emit(new { t = "err", text = err });
        }

        var saved = new List<string>();
        foreach (Match m in Regex.Matches(full, @"\[\[SAVE:\s*(.+?)\]\]", RegexOptions.Singleline))
            saved.Add(m.Groups[1].Value.Trim());
        foreach (var s in saved) await Db.SaveMemory(cfg, s);

        await Emit(new { t = "done", provider, saved });
    }
    catch (OperationCanceledException) { }
    catch (Exception ex)
    {
        try { await Emit(new { t = "err", text = ex.Message }); } catch { }
    }
});
app.MapPost("/see", async (SeeReq req, IConfiguration cfg, IHttpClientFactory f) =>
{
    var b64 = req.Image ?? "";
    var comma = b64.IndexOf(',');
    if (comma >= 0) b64 = b64[(comma + 1)..];
    if (b64.Length < 200 || b64.Length > 900000)
        return Results.Json(new { state = "unsure", error = "tasveer ka size theek nahi" });

    var prompt =
        "This is one small webcam snapshot from a laptop. Look at the person (if any) and decide what they are doing. " +
        "Reply ONLY with JSON like {\"state\":\"awake\"}. state must be exactly one of: " +
        "\"awake\" (a person is visible and awake, for example sitting, looking at the screen, talking or moving), " +
        "\"asleep\" (the person is clearly sleeping: eyes closed AND lying down or head resting, not just blinking or looking down), " +
        "\"away\" (no person is visible), " +
        "\"unsure\" (too dark, blurry or unclear). Do not identify anyone.";

    var text = await VisionGroq.Ask(cfg, f, b64, prompt, true);
    if (string.IsNullOrWhiteSpace(text))
        return Results.Json(new { state = "unsure", error = string.IsNullOrEmpty(VisionGroq.LastError) ? "vision jawab nahi de saka" : VisionGroq.LastError });
    try
    {
        using var doc = JsonDocument.Parse(VisionGroq.ExtractJson(text));
        var st = doc.RootElement.TryGetProperty("state", out var s) ? (s.GetString() ?? "unsure") : "unsure";
        st = st.ToLowerInvariant();
        if (st != "awake" && st != "asleep" && st != "away") st = "unsure";
        return Results.Json(new { state = st });
    }
    catch { return Results.Json(new { state = "unsure" }); }
});
// app.MapPost("/stt", async (HttpRequest rq, IConfiguration cfg, IHttpClientFactory f) =>
// {
//     var key = cfg["Groq:ApiKey"];
//     if (string.IsNullOrEmpty(key)) return Results.Json(new { text = "", error = "Groq key set nahi hai" });
//     using var ms = new MemoryStream();
//     await rq.Body.CopyToAsync(ms);
//     if (ms.Length < 3000 || ms.Length > 8_000_000) return Results.Json(new { text = "" });

//     var form = new MultipartFormDataContent();
//     var audio = new ByteArrayContent(ms.ToArray());
//     audio.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("audio/wav");
//     form.Add(audio, "file", "speech.wav");
//     form.Add(new StringContent(cfg["Groq:SttModel"] ?? "whisper-large-v3-turbo"), "model");
//     form.Add(new StringContent("ur"), "language");
//     form.Add(new StringContent("0"), "temperature");
//     form.Add(new StringContent("Hello Nova. Nova, gaana pause karo. YouTube kholo. Volume kam karo. Ye code check karo."), "prompt");

//     var msg = new HttpRequestMessage(HttpMethod.Post, "https://api.groq.com/openai/v1/audio/transcriptions") { Content = form };
//     msg.Headers.Add("Authorization", "Bearer " + key);
//     var res = await f.CreateClient().SendAsync(msg);
//     Usage.Add("groq-stt");
//     var json = await res.Content.ReadAsStringAsync();
//     if (!res.IsSuccessStatusCode) return Results.Json(new { text = "", error = json });
//     using var doc = JsonDocument.Parse(json);
//     var text = doc.RootElement.TryGetProperty("text", out var tx) ? tx.GetString() ?? "" : "";
//     return Results.Json(new { text });
// });
app.MapPost("/stt", async (HttpRequest rq, IConfiguration cfg, IHttpClientFactory f) =>
{
    try
    {
        var key = cfg["Groq:ApiKey"];
        if (string.IsNullOrEmpty(key)) return Results.Json(new { text = "", error = "Groq key set nahi hai" });
        using var ms = new MemoryStream();
        await rq.Body.CopyToAsync(ms);
        if (ms.Length < 3000 || ms.Length > 8_000_000)
            return Results.Json(new { text = "", error = "awaaz ka size theek nahi: " + ms.Length });

        var form = new MultipartFormDataContent();
        var audio = new ByteArrayContent(ms.ToArray());
        audio.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("audio/wav");
        form.Add(audio, "file", "speech.wav");
        form.Add(new StringContent(cfg["Groq:SttModel"] ?? "whisper-large-v3-turbo"), "model");
        form.Add(new StringContent("ur"), "language");
        form.Add(new StringContent("0"), "temperature");
        form.Add(new StringContent("Hello Nova. Nova, gaana pause karo. YouTube kholo. Volume kam karo. Ye code check karo."), "prompt");

        var msg = new HttpRequestMessage(HttpMethod.Post, "https://api.groq.com/openai/v1/audio/transcriptions") { Content = form };
        msg.Headers.Add("Authorization", "Bearer " + key);
        var res = await f.CreateClient().SendAsync(msg);
        Usage.Add("groq-stt");
        var json = await res.Content.ReadAsStringAsync();
        if (!res.IsSuccessStatusCode) return Results.Json(new { text = "", error = json });
        using var doc = JsonDocument.Parse(json);
        var text = doc.RootElement.TryGetProperty("text", out var tx) ? tx.GetString() ?? "" : "";
        return Results.Json(new { text });
    }
    catch (Exception ex)
    {
        Console.WriteLine("STT ERROR: " + ex);
        return Results.Json(new { text = "", error = ex.Message });
    }
});
app.Run();

record HistoryItem(string Role, string Text);
record ChatRequest(string Message, List<HistoryItem>? History, string? Lang, string? Device);
record MemoryItem(Guid Id, string Content);
record HabitReq(string Name);
record SeeReq(string? Image);
record AuthReq(string? Email, string? Password, string? Invite);

class ToolAcc
{
    public string Id = "";
    public string Name = "";
    public StringBuilder Args = new();
}

static class Usage
{
    static readonly object L = new();
    static DateTime day = DateTime.Now.Date;
    static readonly Dictionary<string, int> c = new();

    public static void Add(string key)
    {
        lock (L)
        {
            if (DateTime.Now.Date != day) { c.Clear(); day = DateTime.Now.Date; }
            c[key] = c.GetValueOrDefault(key) + 1;
        }
    }

    public static object Get()
    {
        lock (L) return new { date = day.ToString("yyyy-MM-dd"), counts = new Dictionary<string, int>(c) };
    }
}

static class Safety
{
    static readonly object L = new();
    static readonly Dictionary<Guid, (string tool, JsonElement args, DateTime until)> P = new();
    static Guid K => CurrentUser.Id.Value ?? Guid.Empty;

    static readonly string[] Words =
    {
        "delete", "remove", "uninstall", "format", "erase", "send", "buy", "purchase",
        "pay", "checkout", "order", "submit", "post", "publish", "transfer"
    };

    public static bool NeedsConfirm(string name, JsonElement a)
    {
        if (name == "shutdown_pc") return true;
        if (name == "click_on" && a.ValueKind == JsonValueKind.Object && a.TryGetProperty("target", out var t))
        {
            var s = (t.GetString() ?? "").ToLower();
            return Words.Any(w => Regex.IsMatch(s, @"\b" + w + @"\b"));
        }
        return false;
    }

    public static void Set(string name, JsonElement a)
    {
        lock (L)
        {
            foreach (var old in P.Where(x => x.Value.until < DateTime.UtcNow).Select(x => x.Key).ToList()) P.Remove(old);
            P[K] = (name, a.ValueKind == JsonValueKind.Undefined ? default : a.Clone(), DateTime.UtcNow.AddSeconds(30));
        }
    }

    public static bool HasPending
    {
        get { lock (L) return P.TryGetValue(K, out var p) && DateTime.UtcNow < p.until; }
    }

    public static (string? name, JsonElement args) Take()
    {
        lock (L)
        {
            if (!P.Remove(K, out var p)) return (null, default);
            return (DateTime.UtcNow < p.until ? p.tool : null, p.args);
        }
    }

    public static void Clear() { lock (L) P.Remove(K); }
}

static class VisionGroq
{
    public static string LastError = "";

    public static async Task<string?> Ask(IConfiguration cfg, IHttpClientFactory f, string b64, string prompt, bool asJson)
    {
        var key = cfg["Groq:ApiKey"];
        var model = cfg["Groq:VisionModel"];
        if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(model))
        {
            LastError = "Groq:ApiKey ya Groq:VisionModel set nahi hai";
            return null;
        }
        try
        {
            var body = new JsonObject
            {
                ["model"] = model,
                ["messages"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["role"] = "user",
                        ["content"] = new JsonArray
                        {
                            new JsonObject { ["type"] = "text", ["text"] = prompt },
                            new JsonObject
                            {
                                ["type"] = "image_url",
                                ["image_url"] = new JsonObject { ["url"] = "data:image/jpeg;base64," + b64 }
                            }
                        }
                    }
                }
            };
            if (asJson) body["response_format"] = new JsonObject { ["type"] = "json_object" };

            var msg = new HttpRequestMessage(HttpMethod.Post, "https://api.groq.com/openai/v1/chat/completions");
            msg.Headers.Add("Authorization", "Bearer " + key);
            msg.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
            var res = await f.CreateClient().SendAsync(msg);
            Usage.Add("groq-vision");
            var json = await res.Content.ReadAsStringAsync();
            if (!res.IsSuccessStatusCode)
            {
                LastError = json;
                Console.WriteLine("Groq vision error: " + json);
                return null;
            }
            using var doc = JsonDocument.Parse(json);
            var content = doc.RootElement.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString();
            return content == null ? null : Regex.Replace(content, "<think>.*?</think>", "", RegexOptions.Singleline).Trim();
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            Console.WriteLine("Groq vision exception: " + ex.Message);
            return null;
        }
    }

    public static string ExtractJson(string s)
    {
        var a = s.IndexOf('{');
        var b = s.LastIndexOf('}');
        return a >= 0 && b > a ? s.Substring(a, b - a + 1) : s.Trim();
    }
}

static class Talk
{
    public static string Clean(string s)
    {
        s = Regex.Replace(s, @"\[([^\]]*)\]\([^)]*\)", "$1");
        s = Regex.Replace(s, @"[*#`_~>|]", "");
        s = Regex.Replace(s, @"\s+", " ").Trim();
        return s;
    }

    // Jumlon mein todta hai. Jumla tab poora maana jata hai jab '.', '!', '?' ke baad space aaye.
    public static (List<string> sents, string rest) Split(string buf, bool flush)
    {
        var list = new List<string>();
        while (true)
        {
            int cut = -1;
            for (int i = 0; i < buf.Length; i++)
            {
                char ch = buf[i];
                if (ch == '\n') { cut = i; break; }
                if ((ch == '.' || ch == '!' || ch == '?' || ch == '۔' || ch == '؟')
                    && i >= 14 && i + 1 < buf.Length && char.IsWhiteSpace(buf[i + 1]))
                { cut = i; break; }
            }
            if (cut < 0) break;
            list.Add(buf.Substring(0, cut + 1));
            buf = buf.Substring(cut + 1);
        }
        if (flush && buf.Trim().Length > 0) { list.Add(buf); buf = ""; }
        return (list, buf);
    }

    static async Task<(HttpResponseMessage? resp, string err)> OpenStream(
        IConfiguration cfg, IHttpClientFactory f, JsonArray messages, JsonArray tools, CancellationToken ct)
    {
        var key = cfg["Groq:ApiKey"];
        if (string.IsNullOrEmpty(key)) return (null, "Groq key set nahi hai");
        var models = new[] { cfg["Groq:Model"] ?? "openai/gpt-oss-120b", cfg["Groq:Fallback"] ?? "openai/gpt-oss-20b" };
        string last = "";
        foreach (var model in models)
        {
            bool effort = model.Contains("gpt-oss");
            for (int attempt = 0; attempt < 3; attempt++)
            {
                var body = new JsonObject
                {
                    ["model"] = model,
                    ["messages"] = JsonNode.Parse(messages.ToJsonString()),
                    ["tools"] = JsonNode.Parse(tools.ToJsonString()),
                    ["tool_choice"] = "auto",
                    ["stream"] = true
                };
                if (effort) body["reasoning_effort"] = "low";

                var msg = new HttpRequestMessage(HttpMethod.Post, "https://api.groq.com/openai/v1/chat/completions");
                msg.Headers.Add("Authorization", "Bearer " + key);
                msg.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
                var res = await f.CreateClient().SendAsync(msg, HttpCompletionOption.ResponseHeadersRead, ct);
                Usage.Add("groq");
                if (res.IsSuccessStatusCode) return (res, "");

                var code = (int)res.StatusCode;
                var errText = await res.Content.ReadAsStringAsync(ct);
                last = $"[{model}] {errText}";
                double wait = 5;
                if (res.Headers.TryGetValues("retry-after", out var vals) && double.TryParse(vals.First(), out var ra)) wait = ra;
                res.Dispose();

                if (code == 400 && effort) { effort = false; continue; }
                if (code == 429 && attempt == 0 && wait <= 20)
                {
                    await Task.Delay(TimeSpan.FromSeconds(wait + 0.5), ct);
                    continue;
                }
                break;
            }
        }
        return (null, last);
    }

    public static async Task<(bool ok, string full, string err, bool emitted)> Run(
        IConfiguration cfg, IHttpClientFactory f, string system, List<HistoryItem> history, string message,
        List<string> actions, Func<object, Task> emit, CancellationToken ct)
    {
        var messages = new JsonArray { new JsonObject { ["role"] = "system", ["content"] = system } };
        foreach (var h in history.TakeLast(20))
            messages.Add(new JsonObject { ["role"] = h.Role == "user" ? "user" : "assistant", ["content"] = h.Text });
        messages.Add(new JsonObject { ["role"] = "user", ["content"] = message });
        var tools = Groq.OpenAiTools();

        var all = new StringBuilder();
        bool emitted = false;

        for (int step = 0; step < 6; step++)
        {
            var (resp, err) = await OpenStream(cfg, f, messages, tools, ct);
            if (resp == null) return (false, all.ToString(), err, emitted);

            var stepText = new StringBuilder();
            var calls = new SortedDictionary<int, ToolAcc>();
            var pending = "";
            var tagMode = false;

            async Task Drain(bool flush)
            {
                var (sents, rest) = Split(pending, flush);
                pending = rest;
                foreach (var s in sents)
                {
                    var cs = Clean(s);
                    if (cs.Length == 0) continue;
                    emitted = true;
                    await emit(new { t = "s", text = cs });
                }
            }

            using (resp)
            {
                using var stream = await resp.Content.ReadAsStreamAsync(ct);
                using var reader = new StreamReader(stream);
                string? line;
                while ((line = await reader.ReadLineAsync(ct)) != null)
                {
                    if (!line.StartsWith("data:")) continue;
                    var data = line.Substring(5).Trim();
                    if (data == "[DONE]") break;

                    JsonDocument jd;
                    try { jd = JsonDocument.Parse(data); } catch { continue; }
                    using (jd)
                    {
                        if (!jd.RootElement.TryGetProperty("choices", out var chs) || chs.GetArrayLength() == 0) continue;
                        if (!chs[0].TryGetProperty("delta", out var delta)) continue;

                        if (delta.TryGetProperty("content", out var cEl) && cEl.ValueKind == JsonValueKind.String)
                        {
                            var txt = cEl.GetString() ?? "";
                            if (txt.Length > 0)
                            {
                                stepText.Append(txt);
                                if (!tagMode)
                                {
                                    pending += txt;
                                    var ti = pending.IndexOf("[[", StringComparison.Ordinal);
                                    if (ti >= 0) { pending = pending.Substring(0, ti); tagMode = true; }
                                    await Drain(false);
                                }
                            }
                        }

                        if (delta.TryGetProperty("tool_calls", out var tcs) && tcs.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var tcd in tcs.EnumerateArray())
                            {
                                int idx = tcd.TryGetProperty("index", out var ix) && ix.TryGetInt32(out var ii) ? ii : 0;
                                if (!calls.TryGetValue(idx, out var acc)) { acc = new ToolAcc(); calls[idx] = acc; }
                                if (tcd.TryGetProperty("id", out var idp) && idp.ValueKind == JsonValueKind.String)
                                    acc.Id = idp.GetString() ?? acc.Id;
                                if (tcd.TryGetProperty("function", out var fn))
                                {
                                    if (fn.TryGetProperty("name", out var np) && np.ValueKind == JsonValueKind.String)
                                        acc.Name = np.GetString() ?? acc.Name;
                                    if (fn.TryGetProperty("arguments", out var ap) && ap.ValueKind == JsonValueKind.String)
                                        acc.Args.Append(ap.GetString());
                                }
                            }
                        }
                    }
                }
            }

            await Drain(true);
            all.Append(stepText);

            if (calls.Count == 0) return (true, all.ToString(), "", emitted);

            var tcArr = new JsonArray();
            foreach (var kv in calls)
            {
                var id = string.IsNullOrEmpty(kv.Value.Id) ? "call_" + kv.Key : kv.Value.Id;
                kv.Value.Id = id;
                tcArr.Add(new JsonObject
                {
                    ["id"] = id,
                    ["type"] = "function",
                    ["function"] = new JsonObject { ["name"] = kv.Value.Name, ["arguments"] = kv.Value.Args.ToString() }
                });
            }
            messages.Add(new JsonObject
            {
                ["role"] = "assistant",
                ["content"] = stepText.Length > 0 ? stepText.ToString() : null,
                ["tool_calls"] = tcArr
            });

            foreach (var kv in calls)
            {
                var argsStr = kv.Value.Args.ToString();
                JsonElement args;
                try { args = JsonDocument.Parse(string.IsNullOrWhiteSpace(argsStr) ? "{}" : argsStr).RootElement.Clone(); }
                catch { args = JsonDocument.Parse("{}").RootElement.Clone(); }

                await emit(new { t = "a", name = kv.Value.Name });
                var result = await Agent.ExecTool(cfg, f, kv.Value.Name, args, actions);
                                var po = PhoneBridge.Out.Value;
                if (po != null && po.Count > 0)
                {
                    foreach (var pev in po.ToList()) await emit(pev);
                    po.Clear();
                }
                messages.Add(new JsonObject { ["role"] = "tool", ["tool_call_id"] = kv.Value.Id, ["content"] = result });
            }
        }

        emitted = true;
        await emit(new { t = "s", text = "Ye kaam kuch lamba ho gaya, dobara bol dein." });
        return (true, all.ToString(), "", emitted);
    }
}

static class Agent
{
    public static async Task<string> ExecTool(IConfiguration cfg, IHttpClientFactory f, string name, JsonElement args, List<string> actions)
    {
        string result;
        try { result = await Tools.Run(cfg, f, name, args); }
        catch (Exception ex) { result = "ERROR: " + ex.Message; }
        actions.Add(name);
        if (name != "get_today_log" && name != "wait" && name != "list_reminders"
            && name != "list_tasks" && name != "search_notes" && name != "get_briefing"
            && name != "list_habits" && name != "expense_summary" && name != "evening_checkin" && name != "weekly_review" && name != "read_code")
            await Db.Log(cfg, name + " " + (args.ValueKind == JsonValueKind.Undefined ? "" : args.ToString()), result);
        return result;
    }

    public static async Task<(string? text, string err)> RunGroq(IConfiguration cfg, IHttpClientFactory f,
        string system, List<HistoryItem> history, string message, List<string> actions)
    {
        var messages = new JsonArray { new JsonObject { ["role"] = "system", ["content"] = system } };
        foreach (var h in history.TakeLast(20))
            messages.Add(new JsonObject { ["role"] = h.Role == "user" ? "user" : "assistant", ["content"] = h.Text });
        messages.Add(new JsonObject { ["role"] = "user", ["content"] = message });
        var tools = Groq.OpenAiTools();

        for (int step = 0; step < 8; step++)
        {
            var (ok, json) = await Groq.Call(cfg, f, messages, tools);
            if (!ok) return (null, json);

            using var doc = JsonDocument.Parse(json);
            var msg = doc.RootElement.GetProperty("choices")[0].GetProperty("message");
            var hasCalls = msg.TryGetProperty("tool_calls", out var tc)
                && tc.ValueKind == JsonValueKind.Array && tc.GetArrayLength() > 0;
            string? content = msg.TryGetProperty("content", out var cc) && cc.ValueKind == JsonValueKind.String ? cc.GetString() : null;

            if (!hasCalls) return (content ?? "", "");

            messages.Add(new JsonObject
            {
                ["role"] = "assistant",
                ["content"] = content,
                ["tool_calls"] = JsonNode.Parse(tc.GetRawText())
            });

            foreach (var call in tc.EnumerateArray())
            {
                var id = call.GetProperty("id").GetString();
                var fn = call.GetProperty("function");
                var name = fn.GetProperty("name").GetString()!;
                var argsStr = fn.TryGetProperty("arguments", out var a) ? a.GetString() ?? "{}" : "{}";
                JsonElement args;
                try { args = JsonDocument.Parse(string.IsNullOrWhiteSpace(argsStr) ? "{}" : argsStr).RootElement.Clone(); }
                catch { args = JsonDocument.Parse("{}").RootElement.Clone(); }
                var result = await ExecTool(cfg, f, name, args, actions);
                messages.Add(new JsonObject { ["role"] = "tool", ["tool_call_id"] = id, ["content"] = result });
            }
        }
        return ("Kaam bohat lamba ho gaya, dobara try karein.", "");
    }

    public static async Task<(string? text, string err)> RunGemini(IConfiguration cfg, IHttpClientFactory f,
        string system, List<HistoryItem> history, string message, List<string> actions)
    {
        var contents = new List<object>();
        foreach (var h in history.TakeLast(20))
            contents.Add(new { role = h.Role == "user" ? "user" : "model", parts = new[] { new { text = h.Text } } });
        contents.Add(new { role = "user", parts = new[] { new { text = message } } });

        for (int step = 0; step < 8; step++)
        {
            var body = new
            {
                systemInstruction = new { parts = new[] { new { text = system } } },
                tools = Tools.Active,
                contents
            };
            var (ok, json) = await Gemini.Call(cfg, f, JsonSerializer.Serialize(body));
            if (!ok) return (null, json);

            using var doc = JsonDocument.Parse(json);
            var content = doc.RootElement.GetProperty("candidates")[0].GetProperty("content").Clone();
            var parts = content.TryGetProperty("parts", out var pp) ? pp.EnumerateArray().ToList() : new List<JsonElement>();
            var calls = parts.Where(p => p.TryGetProperty("functionCall", out _)).ToList();

            if (calls.Count == 0)
            {
                var sb = new StringBuilder();
                foreach (var p in parts)
                    if (p.TryGetProperty("text", out var t)) sb.Append(t.GetString());
                return (sb.ToString(), "");
            }

            contents.Add(content);
            var responses = new List<object>();
            foreach (var c in calls)
            {
                var fc = c.GetProperty("functionCall");
                var name = fc.GetProperty("name").GetString()!;
                var args = fc.TryGetProperty("args", out var a) ? a : default;
                var result = await ExecTool(cfg, f, name, args, actions);
                responses.Add(new { functionResponse = new { name, response = new { result } } });
            }
            contents.Add(new { role = "user", parts = responses });
        }
        return ("Kaam bohat lamba ho gaya, dobara try karein.", "");
    }
}

static class Groq
{
    public static JsonArray OpenAiTools()
    {
        var arr = new JsonArray();
        foreach (var d in Tools.Active[0].GetProperty("functionDeclarations").EnumerateArray())
        {
            JsonNode parameters = d.TryGetProperty("parameters", out var p)
                ? Lower(JsonNode.Parse(p.GetRawText())!)
                : JsonNode.Parse("{\"type\":\"object\",\"properties\":{}}")!;
            var fn = new JsonObject
            {
                ["name"] = d.GetProperty("name").GetString(),
                ["description"] = d.GetProperty("description").GetString(),
                ["parameters"] = parameters
            };
            arr.Add(new JsonObject { ["type"] = "function", ["function"] = fn });
        }
        return arr;
    }

    static JsonNode Lower(JsonNode n)
    {
        if (n is JsonObject o)
        {
            foreach (var kv in o.ToList())
            {
                if (kv.Key == "type" && kv.Value is JsonValue v && v.TryGetValue<string>(out var s))
                    o["type"] = s.ToLower();
                else if (kv.Value != null)
                    Lower(kv.Value);
            }
        }
        else if (n is JsonArray a)
        {
            foreach (var x in a) if (x != null) Lower(x);
        }
        return n;
    }

    public static async Task<(bool ok, string json)> Call(IConfiguration cfg, IHttpClientFactory f, JsonArray messages, JsonArray tools)
    {
        var key = cfg["Groq:ApiKey"];
        if (string.IsNullOrEmpty(key)) return (false, "Groq key set nahi hai");
        var models = new[] { cfg["Groq:Model"] ?? "openai/gpt-oss-120b", cfg["Groq:Fallback"] ?? "openai/gpt-oss-20b" };
        string last = "";
        foreach (var model in models)
        {
            for (int attempt = 0; attempt < 2; attempt++)
            {
                var body = new JsonObject
                {
                    ["model"] = model,
                    ["messages"] = JsonNode.Parse(messages.ToJsonString()),
                    ["tools"] = JsonNode.Parse(tools.ToJsonString()),
                    ["tool_choice"] = "auto"
                };
                var msg = new HttpRequestMessage(HttpMethod.Post, "https://api.groq.com/openai/v1/chat/completions");
                msg.Headers.Add("Authorization", "Bearer " + key);
                msg.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
                var res = await f.CreateClient().SendAsync(msg);
                Usage.Add("groq");
                var json = await res.Content.ReadAsStringAsync();
                if (res.IsSuccessStatusCode) return (true, json);
                last = $"[{model}] {json}";

                if ((int)res.StatusCode == 429 && attempt == 0)
                {
                    double wait = 5;
                    if (res.Headers.TryGetValues("retry-after", out var vals) && double.TryParse(vals.First(), out var s)) wait = s;
                    if (wait <= 30)
                    {
                        await Task.Delay(TimeSpan.FromSeconds(wait + 0.5));
                        continue;
                    }
                }
                break;
            }
        }
        return (false, last);
    }
}

static class Gemini
{
    public static async Task<(bool ok, string json)> Call(IConfiguration cfg, IHttpClientFactory f, string payload)
    {
        var key = cfg["Gemini:ApiKey"];
        var models = new[] { cfg["Gemini:Model"] ?? "gemini-3.8-flash", cfg["Gemini:Fallback"] ?? "gemini-3-flash-preview" };
        string last = "";
        foreach (var model in models)
        {
            for (int attempt = 0; attempt < 2; attempt++)
            {
                var msg = new HttpRequestMessage(HttpMethod.Post,
                    $"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent");
                msg.Headers.Add("x-goog-api-key", key);
                msg.Content = new StringContent(payload, Encoding.UTF8, "application/json");
                var res = await f.CreateClient().SendAsync(msg);
                Usage.Add("gemini");
                var json = await res.Content.ReadAsStringAsync();
                if (res.IsSuccessStatusCode) return (true, json);
                last = json;
                if ((int)res.StatusCode == 503) await Task.Delay(1500);
                else break;
            }
        }
        return (false, last);
    }
}

static class Fast
{
    static readonly HashSet<string> Apps = new()
    {
        "chrome", "google chrome", "notepad", "calculator", "paint", "explorer", "file explorer",
        "vscode", "vs code", "settings", "task manager", "spotify", "edge", "word", "excel", "cmd"
    };

    static readonly Dictionary<string, string> Sites = new()
    {
        ["youtube"] = "youtube.com", ["google"] = "google.com", ["gmail"] = "mail.google.com"
    };

    static readonly Dictionary<string, string> ProcessNames = new()
    {
        ["chrome"] = "chrome", ["google chrome"] = "chrome", ["notepad"] = "notepad", ["paint"] = "mspaint",
        ["vscode"] = "code", ["vs code"] = "code", ["spotify"] = "spotify", ["edge"] = "msedge",
        ["word"] = "winword", ["excel"] = "excel"
    };

    static JsonElement J(object o) => JsonDocument.Parse(JsonSerializer.Serialize(o)).RootElement.Clone();

    static int Mins(string n, string unit)
    {
        var v = int.Parse(n);
        return unit.StartsWith("h") || unit.StartsWith("g") ? v * 60 : v;
    }

    public static async Task<string?> TryRun(IConfiguration cfg, IHttpClientFactory f, string raw, List<string> actions)
    {
        var t = Regex.Replace(raw.ToLower(), @"\b(jarvis|please|plz|zara)\b|[.,!?]", " ");
        t = Regex.Replace(t, @"\s+", " ").Trim();
        if (t.Length == 0) return null;

        async Task<string> Do(string tool, object args, string ok = "Done.")
        {
            try
            {
                var a = J(args);
                var r = await Tools.Run(cfg, f, tool, a);
                if (r.StartsWith("NEEDS_CONFIRMATION"))
                    return "Pakka? Confirm ke liye 'yes' ya 'haan' bolein, cancel ke liye 'no'.";
                if (r.StartsWith("ERROR") || r.StartsWith("NOT FOUND") || r.StartsWith("AMBIGUOUS")) return r;
                actions.Add(tool + " (local)");
                Usage.Add("local");
                await Db.Log(cfg, tool + " " + a, r);
                return ok == "Done." ? "Done." : ok + " (" + r + ")";
            }
            catch (Exception ex) { return "Error: " + ex.Message; }
        }

        async Task<string> Spend(string amount, string what)
        {
            what = what.Trim();
            return await Do("log_expense",
                new { amount = double.Parse(amount, CultureInfo.InvariantCulture), note = what, category = Life.Guess(what) }, "Saved");
        }

        Match m;

        if (Safety.HasPending)
        {
            if (Regex.IsMatch(t, @"^(yes|yeah|yep|confirm|do it|haan|han|ji|ji haan|haan karo|kar do|karo)$"))
            {
                var (pn, pa) = Safety.Take();
                if (pn != null)
                {
                    try
                    {
                        var pr = await Tools.Run(cfg, f, pn, pa, true);
                        actions.Add(pn + " (confirmed)");
                        Usage.Add("local");
                        await Db.Log(cfg, pn + " (confirmed) " + pa, pr);
                        return "Done.";
                    }
                    catch (Exception ex) { return "Error: " + ex.Message; }
                }
            }
            if (Regex.IsMatch(t, @"^(no|nope|cancel|nahi|nahin|na|mat karo|ruko|stop)$"))
            {
                Safety.Clear();
                return "Theek hai, cancel kar diya.";
            }
        }

        // ---- Reminders / timer ----
        m = Regex.Match(t, @"^(?:remind me|set a reminder|set reminder) (?:in|after) (\d+) (minutes?|mins?|hours?|hrs?) (?:to|that|for) (.+)$");
        if (m.Success)
            return await Do("set_reminder", new { text = m.Groups[3].Value.Trim(), minutes = Mins(m.Groups[1].Value, m.Groups[2].Value) }, "Reminder set");

        m = Regex.Match(t, @"^(?:set (?:a )?)?timer (?:for )?(\d+) (minutes?|mins?|hours?|hrs?)$");
        if (m.Success)
            return await Do("set_reminder", new { text = "Timer khatam ho gaya", minutes = Mins(m.Groups[1].Value, m.Groups[2].Value) }, "Timer set");

        m = Regex.Match(t, @"^(\d+) (minute|minutes|min|mins|ghanta|ghante|hour|hours) (?:baad|bad) (.+?) (?:yaad dilao|yaad dila do|yaad karao|yaad karwao|remind kar do)$");
        if (m.Success)
            return await Do("set_reminder", new { text = m.Groups[3].Value.Trim(), minutes = Mins(m.Groups[1].Value, m.Groups[2].Value) }, "Reminder set");

        // ---- Simple task (bina tareekh ke) ----
        m = Regex.Match(t, @"^(?:add|new|create|make) (?:a |new )?(?:task|todo|to do)(?: to| for| that)? (.+)$");
        if (!m.Success) m = Regex.Match(t, @"^(.+?) (?:task mein daalo|task mein add karo|task add karo|todo mein daalo)$");
        if (m.Success)
        {
            var title = m.Groups[1].Value.Trim();
            if (Regex.IsMatch(title, @"\b(tomorrow|kal|parson|today|aaj|monday|tuesday|wednesday|thursday|friday|saturday|sunday|next week|baje)\b|\bat \d"))
                return null;
            return await Do("add_task", new { title });
        }

        // ---- Kharcha (simple jumle bina AI ke) ----
        m = Regex.Match(t, @"^(?:i )?(?:spent|paid) (?:rs |pkr )?(\d{1,8}) (?:rupees |rupee |rs |pkr |rupay )?(?:on|for) (.+)$");
        if (m.Success) return await Spend(m.Groups[1].Value, m.Groups[2].Value);

        m = Regex.Match(t, @"^(?:add|log|save|note) (?:an )?expense(?: of)? (?:rs |pkr )?(\d{1,8})(?: rupees| rupee| rs| pkr| rupay)?(?: on| for)? (.+)$");
        if (m.Success) return await Spend(m.Groups[1].Value, m.Groups[2].Value);

        m = Regex.Match(t, @"^(\d{1,8}) (?:rupay|rupees|rupe|rs|pkr) (?:ka |ki |ke )?(.+?) (?:liya|li|khareeda|kharch kiye|kharch kiya|kharch hue|kharch hua)$");
        if (m.Success) return await Spend(m.Groups[1].Value, m.Groups[2].Value);

        m = Regex.Match(t, @"^(.+?) (?:pe|par|mein) (\d{1,8}) (?:rupay|rupees|rupe|rs|pkr) (?:kharch|kharcha) (?:kiye|kiya|hue|hua)$");
        if (m.Success) return await Spend(m.Groups[2].Value, m.Groups[1].Value);

        if (Regex.IsMatch(t, @"^(?:undo|delete|remove) (?:the |my )?last expense$"))
            return await Do("undo_last_expense", new { }, "Removed");

        if ((t.Contains("shutdown") || t.Contains("shut down")) && t.Contains("cancel"))
            return await Do("cancel_shutdown", new { });

        if (Regex.IsMatch(t, @"^(shut ?down|turn off|switch off)( the| my)?( pc| computer| laptop)?$|^(pc|computer|laptop) band kar(o| do)?$"))
            return await Do("shutdown_pc", new { });

        if (Regex.IsMatch(t, @"^lock( the| my)?( pc| computer| laptop| screen)?$"))
            return await Do("lock_pc", new { });

        m = Regex.Match(t, @"^(?:volume|awaaz|awaz|sound)\s+(up|down|mute|kam|zyada|zyaada|badhao|barhao|band)(?:\s+kar(?:o| do)?)?$");
        if (m.Success)
        {
            var w = m.Groups[1].Value;
            var act = w is "up" or "zyada" or "zyaada" or "badhao" or "barhao" ? "up" : w is "down" or "kam" ? "down" : "mute";
            return await Do("volume", new { action = act, times = 5 });
        }
        if (t == "mute") return await Do("volume", new { action = "mute" });

        if (Regex.IsMatch(t, @"^(pause|resume|stop|play)( the)?( music| song| video| gaana| gana)?$"))
            return await Do("media", new { action = "play_pause" });
        if (Regex.IsMatch(t, @"^next( song| video| gaana)?$"))
            return await Do("media", new { action = "next" });
        if (Regex.IsMatch(t, @"^(previous|prev|back)( song| video| gaana)?$"))
            return await Do("media", new { action = "previous" });

        m = Regex.Match(t, @"^play (.+?) (?:on|in) youtube$");
        if (!m.Success) m = Regex.Match(t, @"^youtube (?:par|pe) (.+?) (?:chalao|chala do|lagao|laga do|play karo|play kro)$");
        if (!m.Success) m = Regex.Match(t, @"^(.+?) youtube (?:par|pe) (?:chalao|chala do|lagao|laga do)$");
        if (m.Success) return await Do("play_youtube", new { query = m.Groups[1].Value.Trim() });

        m = Regex.Match(t, @"^(?:search|google)(?: for)? (.+)$");
        if (m.Success) return await Do("web_search", new { query = m.Groups[1].Value.Trim() });

        m = Regex.Match(t, @"^(?:open|launch|start) (.+)$");
        if (!m.Success) m = Regex.Match(t, @"^(.+?) (?:kholo|khol do|open karo|open kro)$");
        if (m.Success)
        {
            var name = Regex.Replace(m.Groups[1].Value.Trim(), @"^(the|my)\s+", "");
            if (Sites.TryGetValue(name, out var site)) return await Do("open_url", new { url = site });
            if (Apps.Contains(name)) return await Do("open_app", new { name });
            return null;
        }

        m = Regex.Match(t, @"^close (.+)$");
        if (!m.Success) m = Regex.Match(t, @"^(.+?) band (?:karo|kro|kar do)$");
        if (m.Success)
        {
            var name = m.Groups[1].Value.Trim();
            if (ProcessNames.TryGetValue(name, out var proc)) return await Do("close_app", new { name = proc });
            return null;
        }

        return null;
    }
}

static class ScreenTool
{
    [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] static extern int GetSystemMetrics(int index);

    public static void Init() { if (OperatingSystem.IsWindows()) SetProcessDPIAware(); }

    public static (string b64, int w, int h) Capture()
    {
        int w = GetSystemMetrics(0), h = GetSystemMetrics(1);
        using var bmp = new Bitmap(w, h);
        using (var g = Graphics.FromImage(bmp)) g.CopyFromScreen(0, 0, 0, 0, new Size(w, h));
        int tw = Math.Min(w, 1600), th = h * tw / w;
        using var small = new Bitmap(bmp, tw, th);
        using var ms = new MemoryStream();
        small.Save(ms, ImageFormat.Jpeg);
        return (Convert.ToBase64String(ms.ToArray()), w, h);
    }

    static async Task<string> Ask(IConfiguration cfg, IHttpClientFactory f, string prompt, bool asJson)
    {
        var (b64, _, _) = Capture();

        var viaGroq = await VisionGroq.Ask(cfg, f, b64, prompt, asJson);
        if (!string.IsNullOrWhiteSpace(viaGroq)) return viaGroq;

        var body = new Dictionary<string, object>
        {
            ["contents"] = new[]
            {
                new
                {
                    role = "user",
                    parts = new object[]
                    {
                        new { inline_data = new { mime_type = "image/jpeg", data = b64 } },
                        new { text = prompt }
                    }
                }
            }
        };
        if (asJson) body["generationConfig"] = new { responseMimeType = "application/json" };

        var (ok, json) = await Gemini.Call(cfg, f, JsonSerializer.Serialize(body));
        if (!ok) throw new Exception("Gemini error: " + json);
        using var doc = JsonDocument.Parse(json);
        var sb = new StringBuilder();
        foreach (var p in doc.RootElement.GetProperty("candidates")[0].GetProperty("content").GetProperty("parts").EnumerateArray())
            if (p.TryGetProperty("text", out var t)) sb.Append(t.GetString());
        return sb.ToString();
    }

    public static Task<string> Describe(IConfiguration cfg, IHttpClientFactory f, string question) =>
        Ask(cfg, f,
            "This is a screenshot of the user's PC screen. " +
            (string.IsNullOrWhiteSpace(question) ? "Describe what is on screen briefly." : question) +
            " Answer in at most 3 short sentences.", false);

    public static async Task<(bool found, int x, int y, string label)> Locate(IConfiguration cfg, IHttpClientFactory f, string target)
    {
        var (_, w, h) = Capture();
        var text = await Ask(cfg, f,
            $"Find this UI element on the screenshot: \"{target}\". " +
            "Reply ONLY with JSON: {\"found\":true,\"point\":[y,x],\"label\":\"what you found\"} where y and x are the CENTER of the element " +
            "as integers normalized to 0-1000 (y from top, x from left). If it is not visible reply {\"found\":false}.", true);
        text = VisionGroq.ExtractJson(text);
        using var doc = JsonDocument.Parse(text);
        var r = doc.RootElement;
        if (!r.TryGetProperty("found", out var fnd) || fnd.ValueKind != JsonValueKind.True) return (false, 0, 0, "");
        var pt = r.GetProperty("point");
        double ny = pt[0].GetDouble(), nx = pt[1].GetDouble();
        int px = (int)Math.Clamp(nx / 1000.0 * w, 0, w - 1);
        int py = (int)Math.Clamp(ny / 1000.0 * h, 0, h - 1);
        var label = r.TryGetProperty("label", out var l) ? l.GetString() ?? "" : "";
        return (true, px, py, label);
    }
}

static class Tools
{
    static JsonElement? _active;
    public static JsonElement Active => _active ??= BuildActive();

    static JsonElement BuildActive()
    {
        if (!Cloud.Enabled) return Declarations;
        var arr = JsonNode.Parse(Declarations.GetRawText())!.AsArray();
        var fds = arr[0]!["functionDeclarations"]!.AsArray();
        for (int i = fds.Count - 1; i >= 0; i--)
            if (Cloud.PcTools.Contains(fds[i]!["name"]!.GetValue<string>())) fds.RemoveAt(i);
        return JsonDocument.Parse(arr.ToJsonString()).RootElement.Clone();
    }

    public static readonly JsonElement Declarations = JsonDocument.Parse("""
    [{"functionDeclarations":[
      {"name":"open_app","description":"Open an app on the PC, e.g. chrome, notepad, calculator, explorer, vscode, spotify, cmd, taskmanager, settings.",
       "parameters":{"type":"OBJECT","properties":{"name":{"type":"STRING"}},"required":["name"]}},
      {"name":"open_url","description":"Open a website URL in the default browser.",
       "parameters":{"type":"OBJECT","properties":{"url":{"type":"STRING"}},"required":["url"]}},
      {"name":"play_youtube","description":"Search YouTube and play the first matching video.",
       "parameters":{"type":"OBJECT","properties":{"query":{"type":"STRING"}},"required":["query"]}},
      {"name":"web_search","description":"Search Google for a query in the browser.",
       "parameters":{"type":"OBJECT","properties":{"query":{"type":"STRING"}},"required":["query"]}},
      {"name":"type_text","description":"Type text into the currently focused window.",
       "parameters":{"type":"OBJECT","properties":{"text":{"type":"STRING"}},"required":["text"]}},
      {"name":"send_keys","description":"Press keys in the focused window using SendKeys syntax: ^ = Ctrl, % = Alt, + = Shift, {ENTER}, {TAB}, {ESC}, {F5}, {DOWN}. Example: ^t opens a new tab, %{F4} closes the window.",
       "parameters":{"type":"OBJECT","properties":{"keys":{"type":"STRING"}},"required":["keys"]}},
      {"name":"move_mouse","description":"Move the mouse to screen pixel coordinates x,y. Prefer click_on when the target can be described.",
       "parameters":{"type":"OBJECT","properties":{"x":{"type":"INTEGER"},"y":{"type":"INTEGER"}},"required":["x","y"]}},
      {"name":"click","description":"Click at the current mouse position.",
       "parameters":{"type":"OBJECT","properties":{"button":{"type":"STRING","description":"left or right"},"double":{"type":"BOOLEAN"}}}},
      {"name":"look_at_screen","description":"Take a screenshot and answer a question about what is currently on the screen.",
       "parameters":{"type":"OBJECT","properties":{"question":{"type":"STRING","description":"What to find out. Empty means describe the screen."}}}},
      {"name":"click_on","description":"Find a UI element on the screen by description (button, link, icon, text, video) and click it with the mouse.",
       "parameters":{"type":"OBJECT","properties":{"target":{"type":"STRING","description":"Description of what to click, e.g. 'the red Subscribe button'"},"button":{"type":"STRING","description":"left or right"},"double":{"type":"BOOLEAN"}},"required":["target"]}},
      {"name":"wait","description":"Wait a few seconds, e.g. for an app or page to finish loading.",
       "parameters":{"type":"OBJECT","properties":{"seconds":{"type":"INTEGER"}},"required":["seconds"]}},
      {"name":"volume","description":"Change system volume.",
       "parameters":{"type":"OBJECT","properties":{"action":{"type":"STRING","description":"up, down or mute"},"times":{"type":"INTEGER","description":"each step is about 2 percent"}},"required":["action"]}},
      {"name":"media","description":"Control media playback.",
       "parameters":{"type":"OBJECT","properties":{"action":{"type":"STRING","description":"play_pause, next or previous"}},"required":["action"]}},
      {"name":"close_app","description":"Politely close an app by its process name, e.g. chrome, notepad.",
       "parameters":{"type":"OBJECT","properties":{"name":{"type":"STRING"}},"required":["name"]}},
      {"name":"lock_pc","description":"Lock the PC screen."},
      {"name":"shutdown_pc","description":"Shut down the PC after a 30 second timer. Requires user confirmation."},
      {"name":"cancel_shutdown","description":"Cancel a pending shutdown."},
      {"name":"set_reminder","description":"Set a reminder or timer that will be spoken and shown at the right time. Give either minutes (relative) or at (clock time).",
       "parameters":{"type":"OBJECT","properties":{"text":{"type":"STRING","description":"What to remind the user about"},"minutes":{"type":"INTEGER","description":"Minutes from now"},"at":{"type":"STRING","description":"24-hour HH:mm in Pakistan time, e.g. 21:30"}},"required":["text"]}},
      {"name":"list_reminders","description":"List the pending reminders."},
      {"name":"clear_reminders","description":"Delete all pending reminders."},
      {"name":"add_task","description":"Add a to-do task for the user, optionally with a due date and a priority.",
       "parameters":{"type":"OBJECT","properties":{"title":{"type":"STRING"},"due_date":{"type":"STRING","description":"Due date as YYYY-MM-DD, optional"},"priority":{"type":"STRING","description":"high, normal or low"}},"required":["title"]}},
      {"name":"list_tasks","description":"List the user's tasks. filter is pending (default), today (due today or overdue) or done (finished today).",
       "parameters":{"type":"OBJECT","properties":{"filter":{"type":"STRING"}}}},
      {"name":"complete_task","description":"Mark a pending task as done by matching a few words of its title.",
       "parameters":{"type":"OBJECT","properties":{"match":{"type":"STRING"}},"required":["match"]}},
      {"name":"add_note","description":"Save a personal note, idea or diary entry for later.",
       "parameters":{"type":"OBJECT","properties":{"content":{"type":"STRING"},"tag":{"type":"STRING","description":"Optional category such as idea, work, personal or diary"}},"required":["content"]}},
      {"name":"search_notes","description":"Search the saved notes. An empty query returns the latest notes.",
       "parameters":{"type":"OBJECT","properties":{"query":{"type":"STRING"}}}},
      {"name":"get_briefing","description":"Get a summary of the user's day: pending tasks, reminders and recent work notes. Use it for good morning or what is my day."},
      {"name":"log_expense","description":"Record money the user spent, in Pakistani rupees. Category is one of food, transport, bills, shopping, health, study, entertainment or other.",
       "parameters":{"type":"OBJECT","properties":{"amount":{"type":"NUMBER"},"category":{"type":"STRING"},"note":{"type":"STRING","description":"What it was for"}},"required":["amount"]}},
      {"name":"expense_summary","description":"Summarise the user's spending for a period: today, week (last 7 days) or month (this month).",
       "parameters":{"type":"OBJECT","properties":{"period":{"type":"STRING"}}}},
      {"name":"undo_last_expense","description":"Delete the most recently logged expense, for mistakes."},
      {"name":"add_habit","description":"Start tracking a daily habit, for example Exercise, Quran, Read 20 pages or Drink water.",
       "parameters":{"type":"OBJECT","properties":{"name":{"type":"STRING"}},"required":["name"]}},
      {"name":"complete_habit","description":"Mark a habit as done for today by matching a few words of its name.",
       "parameters":{"type":"OBJECT","properties":{"name":{"type":"STRING"}},"required":["name"]}},
      {"name":"remove_habit","description":"Stop tracking a habit by matching a few words of its name.",
       "parameters":{"type":"OBJECT","properties":{"name":{"type":"STRING"}},"required":["name"]}},
      {"name":"list_habits","description":"List the tracked habits with today's status and streaks."},
      {"name":"log_mood","description":"Record how the user feels today on a scale from 1 (very bad) to 10 (excellent).",
       "parameters":{"type":"OBJECT","properties":{"score":{"type":"INTEGER"},"note":{"type":"STRING"}},"required":["score"]}},
      {"name":"evening_checkin","description":"Get today's achievements, what is still left, today's spending and mood status, for the evening check-in."},
      {"name":"weekly_review","description":"Get the last 7 days of tasks, spending, habits, mood and work notes, compared with the week before, to write a weekly review."},
          {"name":"phone_open_app","description":"Open an app on the USER'S ANDROID PHONE by its name (WhatsApp, YouTube, Camera, Chrome, Settings...). Only when the user is talking from the phone app.",
       "parameters":{"type":"OBJECT","properties":{"name":{"type":"STRING"}},"required":["name"]}},
      {"name":"phone_open_url","description":"Open a web address on the user's phone.",
       "parameters":{"type":"OBJECT","properties":{"url":{"type":"STRING"}},"required":["url"]}},
      {"name":"phone_call","description":"Open the phone dialer for a contact name or a number. The user must press the call button.",
       "parameters":{"type":"OBJECT","properties":{"who":{"type":"STRING"}},"required":["who"]}},
      {"name":"phone_sms","description":"Open the SMS compose screen for a contact name or number with a prepared text. The user must press send.",
       "parameters":{"type":"OBJECT","properties":{"who":{"type":"STRING"},"text":{"type":"STRING"}},"required":["who"]}},
      {"name":"phone_flashlight","description":"Turn the phone flashlight on or off.",
       "parameters":{"type":"OBJECT","properties":{"on":{"type":"BOOLEAN"}},"required":["on"]}},
      {"name":"phone_alarm","description":"Set an alarm on the phone for a clock time (24-hour).",
       "parameters":{"type":"OBJECT","properties":{"hour":{"type":"INTEGER"},"minute":{"type":"INTEGER"},"label":{"type":"STRING"}},"required":["hour","minute"]}},
      {"name":"phone_timer","description":"Start a countdown timer on the phone.",
       "parameters":{"type":"OBJECT","properties":{"seconds":{"type":"INTEGER"}},"required":["seconds"]}},
      {"name":"phone_volume","description":"Change the phone media volume.",
       "parameters":{"type":"OBJECT","properties":{"action":{"type":"STRING","description":"up, down or mute"}},"required":["action"]}},
      {"name":"phone_navigate","description":"Open maps on the phone for a place or an address.",
       "parameters":{"type":"OBJECT","properties":{"query":{"type":"STRING"}},"required":["query"]}},
      {"name":"phone_settings","description":"Open a phone settings page: wifi, bluetooth, display, sound, battery, airplane or general.",
       "parameters":{"type":"OBJECT","properties":{"page":{"type":"STRING"}},"required":["page"]}},
             {"name":"read_code","description":"Read code or text from the user's PC so you can review it. Use when the user asks if their code is correct, or asks to check or review code or text they are working on. copy_selection presses Ctrl+C first to copy what the user selected. whole_file selects everything in the open editor and copies it. If both are false only the current clipboard is read.",
       "parameters":{"type":"OBJECT","properties":{"copy_selection":{"type":"BOOLEAN"},"whole_file":{"type":"BOOLEAN"}}}},
             {"name":"log_work","description":"Save a short note about work the user did or is doing.",
       "parameters":{"type":"OBJECT","properties":{"note":{"type":"STRING"}},"required":["note"]}},
      {"name":"get_today_log","description":"Get everything logged today (actions and work notes) to write the daily report."}
    ]}]
    """).RootElement.Clone();

    [DllImport("user32.dll")] static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] static extern void mouse_event(uint f, uint dx, uint dy, uint d, UIntPtr e);
    [DllImport("user32.dll")] static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr e);

    static string S(JsonElement a, string k) =>
        a.ValueKind == JsonValueKind.Object && a.TryGetProperty(k, out var v) ? (v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ToString()) : "";
    static int I(JsonElement a, string k, int d = 0) =>
        a.ValueKind == JsonValueKind.Object && a.TryGetProperty(k, out var v) && v.TryGetInt32(out var n) ? n : d;
    static bool B(JsonElement a, string k) =>
        a.ValueKind == JsonValueKind.Object && a.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.True;
    static double? D(JsonElement a, string k)
    {
        if (a.ValueKind != JsonValueKind.Object || !a.TryGetProperty(k, out var v)) return null;
        if (v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var d1)) return d1;
        if (v.ValueKind == JsonValueKind.String &&
            double.TryParse(v.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d2)) return d2;
        return null;
    }

    static void Open(string target) =>
        Process.Start(new ProcessStartInfo(target) { UseShellExecute = true });

    static void Key(byte vk) { keybd_event(vk, 0, 0, UIntPtr.Zero); keybd_event(vk, 0, 2, UIntPtr.Zero); }

    static async Task ClickHere(bool right, bool dbl)
    {
        uint down = right ? 0x0008u : 0x0002u, up = right ? 0x0010u : 0x0004u;
        int n = dbl ? 2 : 1;
        for (int i = 0; i < n; i++)
        {
            mouse_event(down, 0, 0, 0, UIntPtr.Zero);
            mouse_event(up, 0, 0, 0, UIntPtr.Zero);
            await Task.Delay(80);
        }
    }

    static void SendKeys(string keys)
    {
        var psi = new ProcessStartInfo("powershell",
            "-NoProfile -WindowStyle Hidden -Command \"Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait($env:JKEYS)\"")
        { UseShellExecute = false, CreateNoWindow = true };
        psi.Environment["JKEYS"] = keys;
        Process.Start(psi)!.WaitForExit(8000);
    }

    public static async Task<string> Run(IConfiguration cfg, IHttpClientFactory f, string name, JsonElement a, bool confirmed = false)
    {
        if (Cloud.Enabled && Cloud.PcTools.Contains(name))
            return "ERROR: PC control is cloud version mein abhi available nahi. Phone aur personal tools chalte hain.";
        if (!confirmed && Safety.NeedsConfirm(name, a))
        {
            Safety.Set(name, a);
            return "NEEDS_CONFIRMATION: This action was NOT executed. Ask the user to say yes to confirm (within 30 seconds).";
        }

        switch (name)
        {
            case "open_app":
            {
                var n = S(a, "name").ToLower().Trim();
                var map = new Dictionary<string, string>
                {
                    ["chrome"] = "chrome", ["google chrome"] = "chrome", ["notepad"] = "notepad",
                    ["calculator"] = "calc", ["calc"] = "calc", ["explorer"] = "explorer",
                    ["file explorer"] = "explorer", ["vscode"] = "code", ["vs code"] = "code",
                    ["cmd"] = "cmd", ["command prompt"] = "cmd", ["taskmanager"] = "taskmgr",
                    ["task manager"] = "taskmgr", ["settings"] = "ms-settings:", ["spotify"] = "spotify",
                    ["paint"] = "mspaint", ["edge"] = "msedge", ["word"] = "winword", ["excel"] = "excel"
                };
                Open(map.TryGetValue(n, out var exe) ? exe : n);
                return "opened " + n;
            }
            case "open_url":
            {
                var u = S(a, "url");
                if (!u.StartsWith("http")) u = "https://" + u;
                Open(u);
                return "opened " + u;
            }
            case "web_search":
                Open("https://www.google.com/search?q=" + Uri.EscapeDataString(S(a, "query")));
                return "searched";
            case "play_youtube":
            {
                var q = S(a, "query");
                var searchUrl = "https://www.youtube.com/results?search_query=" + Uri.EscapeDataString(q);
                try
                {
                    var req = new HttpRequestMessage(HttpMethod.Get, searchUrl);
                    req.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120 Safari/537.36");
                    req.Headers.Add("Accept-Language", "en-US,en;q=0.9");
                    var html = await (await f.CreateClient().SendAsync(req)).Content.ReadAsStringAsync();
                    var m = Regex.Match(html, "\"videoId\":\"([\\w-]{11})\"");
                    if (m.Success)
                    {
                        Open("https://www.youtube.com/watch?v=" + m.Groups[1].Value);
                        return "playing first result for " + q;
                    }
                }
                catch { }
                Open(searchUrl);
                return "could not pick a video, opened search results for " + q;
            }
            case "type_text":
            {
                var t = Regex.Replace(S(a, "text"), @"[{}\[\]()+^%~]", m => "{" + m.Value + "}");
                SendKeys(t);
                return "typed";
            }
            case "send_keys":
                SendKeys(S(a, "keys"));
                return "keys sent";
            case "move_mouse":
                SetCursorPos(I(a, "x"), I(a, "y"));
                return "mouse moved";
            case "click":
                await ClickHere(S(a, "button").ToLower() == "right", B(a, "double"));
                return "clicked";
            case "look_at_screen":
                return await ScreenTool.Describe(cfg, f, S(a, "question"));
            case "click_on":
            {
                var target = S(a, "target");
                var (found, x, y, label) = await ScreenTool.Locate(cfg, f, target);
                if (!found) return "NOT FOUND: could not see '" + target + "' on the screen";
                SetCursorPos(x, y);
                await Task.Delay(200);
                await ClickHere(S(a, "button").ToLower() == "right", B(a, "double"));
                return $"clicked '{label}' at {x},{y}";
            }
            case "wait":
                await Task.Delay(Math.Clamp(I(a, "seconds", 2), 1, 10) * 1000);
                return "waited";
            case "volume":
            {
                var act = S(a, "action").ToLower();
                int times = Math.Clamp(I(a, "times", 5), 1, 50);
                byte vk = act == "up" ? (byte)0xAF : act == "down" ? (byte)0xAE : (byte)0xAD;
                for (int i = 0; i < (act == "mute" ? 1 : times); i++) Key(vk);
                return "volume " + act;
            }
            case "media":
            {
                var act = S(a, "action").ToLower();
                Key(act == "next" ? (byte)0xB0 : act == "previous" ? (byte)0xB1 : (byte)0xB3);
                return "media " + act;
            }
            case "close_app":
            {
                var n = S(a, "name").ToLower().Replace(".exe", "");
                int c = 0;
                foreach (var p in Process.GetProcessesByName(n)) { p.CloseMainWindow(); c++; }
                return c > 0 ? $"asked {c} window(s) of {n} to close" : "no running app named " + n;
            }
            case "lock_pc":
                Process.Start(new ProcessStartInfo("rundll32.exe", "user32.dll,LockWorkStation") { UseShellExecute = false });
                return "locked";
            case "shutdown_pc":
                Process.Start(new ProcessStartInfo("shutdown", "/s /t 30") { UseShellExecute = false, CreateNoWindow = true });
                return "shutdown in 30 seconds";
            case "cancel_shutdown":
                Process.Start(new ProcessStartInfo("shutdown", "/a") { UseShellExecute = false, CreateNoWindow = true });
                return "shutdown cancelled";
            case "set_reminder":
            {
                var text = S(a, "text").Trim();
                if (text.Length == 0) return "ERROR: reminder ka text khali hai";
                var at = S(a, "at").Trim();
                int mins = I(a, "minutes", 0);
                DateTime dueUtc;
                if (Regex.IsMatch(at, @"^\d{1,2}:\d{2}$") && TimeSpan.TryParse(at, out var tod) && tod < TimeSpan.FromHours(24))
                {
                    var tz = Db.Pk();
                    var nowPk = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, tz);
                    var target = nowPk.Date + tod;
                    if (target <= nowPk) target = target.AddDays(1);
                    dueUtc = TimeZoneInfo.ConvertTimeToUtc(target, tz);
                }
                else if (mins > 0) dueUtc = DateTime.UtcNow.AddMinutes(mins);
                else return "ERROR: minutes ya at (HH:mm) dena zaroori hai";

                await Db.AddReminder(cfg, text, dueUtc);
                var shown = TimeZoneInfo.ConvertTimeFromUtc(dueUtc, Db.Pk()).ToString("dd MMM HH:mm");
                return "reminder set for " + shown;
            }
            case "list_reminders":
                return await Db.ListReminders(cfg);
            case "clear_reminders":
                return "cleared " + await Db.ClearReminders(cfg) + " reminders";
            case "add_task":
            {
                var title = S(a, "title").Trim();
                if (title.Length == 0) return "ERROR: task ka title khali hai";
                DateOnly? due = null;
                if (DateOnly.TryParseExact(S(a, "due_date"), "yyyy-MM-dd",
                        CultureInfo.InvariantCulture, DateTimeStyles.None, out var dd))
                    due = dd;
                var pr = S(a, "priority").ToLower();
                int prio = pr == "high" ? 3 : pr == "low" ? 1 : 2;
                await Db.AddTask(cfg, title, due, prio);
                return "task added: " + title + (due.HasValue ? " (due " + due.Value.ToString("dd MMM") + ")" : "");
            }
            case "list_tasks":
                return await Db.ListTasks(cfg, S(a, "filter"));
            case "complete_task":
                return await Db.CompleteTask(cfg, S(a, "match"));
            case "add_note":
            {
                var content = S(a, "content").Trim();
                if (content.Length == 0) return "ERROR: note khali hai";
                await Db.AddNote(cfg, content, S(a, "tag"));
                return "note saved";
            }
            case "search_notes":
                return await Db.SearchNotes(cfg, S(a, "query"));
            case "get_briefing":
                return await Db.Briefing(cfg);
            case "log_expense":
            {
                var amt = D(a, "amount");
                if (amt == null || double.IsNaN(amt.Value) || double.IsInfinity(amt.Value)) return "ERROR: amount (number) chahiye";
                return await Life.AddExpense(cfg, (decimal)amt.Value, S(a, "category"), S(a, "note"));
            }
            case "expense_summary":
                return await Life.ExpenseSummary(cfg, S(a, "period"));
            case "undo_last_expense":
                return await Life.UndoLastExpense(cfg);
            case "add_habit":
                return await Life.AddHabit(cfg, S(a, "name"));
            case "complete_habit":
                return await Life.CompleteHabit(cfg, S(a, "name"));
            case "remove_habit":
                return await Life.RemoveHabit(cfg, S(a, "name"));
            case "list_habits":
                return await Life.ListHabits(cfg);
            case "log_mood":
                return await Life.LogMood(cfg, (int)Math.Round(D(a, "score") ?? 0), S(a, "note"));
            case "evening_checkin":
                return await Life.EveningCheckin(cfg);
            case "weekly_review":
                return await Life.WeeklyReview(cfg);
                            case "phone_open_app":
            case "phone_open_url":
            case "phone_call":
            case "phone_sms":
            case "phone_flashlight":
            case "phone_alarm":
            case "phone_timer":
            case "phone_volume":
            case "phone_navigate":
            case "phone_settings":
                return PhoneBridge.Send(name, a);
                            case "read_code":
            {
                bool whole = B(a, "whole_file");
                if (whole) { SendKeys("^a"); await Task.Delay(200); }
                if (whole || B(a, "copy_selection")) { SendKeys("^c"); await Task.Delay(500); }
                var cpsi = new ProcessStartInfo("powershell",
                    "-NoProfile -Command \"[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-Clipboard -Raw\"")
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, StandardOutputEncoding = Encoding.UTF8 };
                using var cp = Process.Start(cpsi)!;
                var ctext = (await cp.StandardOutput.ReadToEndAsync()).Trim();
                cp.WaitForExit(5000);
                if (ctext.Length == 0) return "ERROR: clipboard khali hai. Code select karke dobara bolein.";
                if (ctext.Length > 8000) ctext = ctext[..8000] + "\n...(cut)";
                return "CODE:\n" + ctext;
            }
            case "log_work":
                await Db.Log(cfg, "NOTE: " + S(a, "note"), "note");
                return "saved";
            case "get_today_log":
                return await Db.TodayLog(cfg);
            default:
                return "unknown tool " + name;
        }
    }
}

// ---- Life tracker: kharcha, habits, mood, evening check-in, weekly review ----
static class Life
{
    static NpgsqlConnection Conn(IConfiguration cfg) => Db.NewConn(cfg);
    static DateOnly TodayPk() => DateOnly.FromDateTime(TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, Db.Pk()));
    static string M(decimal v) => "Rs " + v.ToString("#,0.##", CultureInfo.InvariantCulture);
    static string Top(string s, int n) =>
        string.Join("\n", s.Split('\n').Select(x => x.TrimEnd()).Where(x => x.Length > 0).Take(n));

    static string PeriodSql(string p) => p switch
    {
        "week" => "spent_at >= now() - interval '7 days'",
        "month" => "date_trunc('month', spent_at at time zone 'Asia/Karachi') = date_trunc('month', now() at time zone 'Asia/Karachi')",
        _ => "(spent_at at time zone 'Asia/Karachi')::date = (now() at time zone 'Asia/Karachi')::date"
    };

    static readonly (string cat, string[] words)[] Cats =
    {
        ("food", new[] { "chai", "tea", "lunch", "dinner", "breakfast", "khana", "food", "biryani", "pizza", "burger", "juice", "snack", "coffee", "restaurant", "nashta", "roti", "dessert", "grocery", "sabzi", "doodh", "milk", "fruit", "fruits", "samosa" }),
        ("transport", new[] { "petrol", "fuel", "diesel", "rickshaw", "uber", "careem", "indrive", "bus", "taxi", "bike", "parking", "ride", "metro", "toll" }),
        ("bills", new[] { "bill", "electricity", "gas", "internet", "wifi", "recharge", "load", "rent", "kiraya", "water", "package" }),
        ("shopping", new[] { "shirt", "shoes", "clothes", "kapray", "kapre", "amazon", "daraz", "shopping", "bag", "watch", "gift" }),
        ("health", new[] { "medicine", "doctor", "hospital", "dawai", "pharmacy", "dentist" }),
        ("study", new[] { "book", "books", "course", "fee", "fees", "stationery", "kitab", "tuition", "udemy" }),
    };

    public static string Guess(string text)
    {
        var t = " " + (text ?? "").ToLowerInvariant() + " ";
        foreach (var (cat, words) in Cats)
            foreach (var w in words)
                if (Regex.IsMatch(t, @"\b" + Regex.Escape(w) + @"\b")) return cat;
        return "other";
    }

    static async Task<decimal> Total(NpgsqlConnection conn, string p)
    {
        await using var cmd = new NpgsqlCommand("select coalesce(sum(amount),0) from expenses where " + PeriodSql(p), conn);
        return Convert.ToDecimal(await cmd.ExecuteScalarAsync());
    }

    // ---- Kharcha ----
    public static async Task<string> AddExpense(IConfiguration cfg, decimal amount, string category, string note)
    {
        if (amount <= 0 || amount > 100000000m) return "ERROR: amount 0 se zyada hona chahiye";
        note = (note ?? "").Trim();
        if (note.Length > 120) note = note[..120];
        category = string.IsNullOrWhiteSpace(category) ? Guess(note) : category.Trim().ToLowerInvariant();
        if (category.Length > 24) category = category[..24];

        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        await using (var cmd = new NpgsqlCommand("insert into expenses (amount, category, note) values (@a, @c, @n)", conn))
        {
            cmd.Parameters.AddWithValue("a", amount);
            cmd.Parameters.AddWithValue("c", category);
            cmd.Parameters.AddWithValue("n", note);
            await cmd.ExecuteNonQueryAsync();
        }
        var today = await Total(conn, "today");
        return $"expense saved: {M(amount)} on {category}" + (note.Length > 0 ? " (" + note + ")" : "") + $". Total today: {M(today)}";
    }

    public static async Task<string> ExpenseSummary(IConfiguration cfg, string period)
    {
        period = (period ?? "today").ToLowerInvariant().Trim();
        if (period != "week" && period != "month") period = "today";
        var where = PeriodSql(period);

        await using var conn = Conn(cfg);
        await conn.OpenAsync();

        var cats = new List<(string c, decimal s)>();
        decimal total = 0;
        await using (var cmd = new NpgsqlCommand(
            "select category, sum(amount) from expenses where " + where + " group by category order by sum(amount) desc", conn))
        await using (var r = await cmd.ExecuteReaderAsync())
            while (await r.ReadAsync())
            {
                var s = r.GetDecimal(1);
                cats.Add((r.GetString(0), s));
                total += s;
            }

        if (cats.Count == 0) return "Is period mein koi kharcha darj nahi (" + period + ").";

        var sb = new StringBuilder();
        sb.AppendLine($"PERIOD: {period}. TOTAL: {M(total)}");
        foreach (var (c, s) in cats) sb.AppendLine($"{c}: {M(s)} ({(int)Math.Round(s / total * 100)}%)");
        sb.AppendLine("LATEST ENTRIES:");
        await using (var cmd2 = new NpgsqlCommand(
            @"select to_char(spent_at at time zone 'Asia/Karachi','DD Mon HH24:MI'), amount, category, coalesce(note,'')
              from expenses where " + where + " order by spent_at desc limit 5", conn))
        await using (var r2 = await cmd2.ExecuteReaderAsync())
            while (await r2.ReadAsync())
                sb.AppendLine($"{r2.GetString(0)} | {M(r2.GetDecimal(1))} | {r2.GetString(2)} | {r2.GetString(3)}");
        return sb.ToString();
    }

    public static async Task<string> UndoLastExpense(IConfiguration cfg)
    {
        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            @"delete from expenses where id = (select id from expenses order by spent_at desc limit 1)
              returning amount, category, coalesce(note,'')", conn);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return "NOT FOUND: koi expense nahi mila";
        var note = r.GetString(2);
        return $"removed last expense: {M(r.GetDecimal(0))} on {r.GetString(1)}" + (note.Length > 0 ? " (" + note + ")" : "");
    }

    // ---- Habits ----
    static int Streak(HashSet<DateOnly> days, DateOnly today)
    {
        var d = days.Contains(today) ? today : today.AddDays(-1);
        int n = 0;
        while (days.Contains(d)) { n++; d = d.AddDays(-1); }
        return n;
    }

    static async Task<List<(Guid id, string name, HashSet<DateOnly> days)>> HabitData(IConfiguration cfg)
    {
        var map = new Dictionary<Guid, (string name, HashSet<DateOnly> days)>();
        var order = new List<Guid>();
        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            @"select h.id, h.name, l.day
              from habits h
              left join habit_logs l on l.habit_id = h.id and l.day >= (now() at time zone 'Asia/Karachi')::date - 120
              where h.active order by h.created_at, h.name", conn);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            var id = r.GetGuid(0);
            if (!map.ContainsKey(id)) { map[id] = (r.GetString(1), new HashSet<DateOnly>()); order.Add(id); }
            if (!r.IsDBNull(2)) map[id].days.Add(r.GetFieldValue<DateOnly>(2));
        }
        return order.Select(id => (id, map[id].name, map[id].days)).ToList();
    }

    public static async Task<string> AddHabit(IConfiguration cfg, string name)
    {
        name = (name ?? "").Trim();
        if (name.Length == 0 || name.Length > 40) return "ERROR: habit ka naam 1 se 40 harf ka hona chahiye";
        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            "insert into habits (name) values (@n) on conflict (user_id, (lower(name))) do update set active = true", conn);
        cmd.Parameters.AddWithValue("n", name);
        await cmd.ExecuteNonQueryAsync();
        return "habit added: " + name;
    }

    static async Task<(Guid id, string name, string? problem)> PickHabit(NpgsqlConnection conn, string match)
    {
        match = (match ?? "").Trim();
        if (match.Length == 0) return (Guid.Empty, "", "ERROR: kaunsi habit? kuch lafz batayein");

        var found = new List<(Guid id, string name)>();
        await using (var cmd = new NpgsqlCommand(
            "select id, name from habits where active and name ilike @m order by created_at limit 6", conn))
        {
            cmd.Parameters.AddWithValue("m", "%" + match.Replace("%", "").Replace("_", "") + "%");
            await using var r = await cmd.ExecuteReaderAsync();
            while (await r.ReadAsync()) found.Add((r.GetGuid(0), r.GetString(1)));
        }

        if (found.Count == 0) return (Guid.Empty, "", "NOT FOUND: koi habit '" + match + "' se match nahi hui");
        if (found.Count == 1) return (found[0].id, found[0].name, null);
        var exact = found.Where(x => x.name.Equals(match, StringComparison.OrdinalIgnoreCase)).ToList();
        if (exact.Count == 1) return (exact[0].id, exact[0].name, null);
        return (Guid.Empty, "", "AMBIGUOUS: kai habits match hui: " + string.Join(" | ", found.Select(x => x.name)) + ". Poora naam batayein.");
    }

    public static async Task<string> CompleteHabit(IConfiguration cfg, string match)
    {
        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        var (id, name, problem) = await PickHabit(conn, match);
        if (problem != null) return problem;

        await using (var ins = new NpgsqlCommand(
            @"insert into habit_logs (habit_id, day) values (@h, (now() at time zone 'Asia/Karachi')::date)
              on conflict do nothing", conn))
        {
            ins.Parameters.AddWithValue("h", id);
            await ins.ExecuteNonQueryAsync();
        }

        var days = new HashSet<DateOnly>();
        await using (var q = new NpgsqlCommand(
            "select day from habit_logs where habit_id = @h and day >= (now() at time zone 'Asia/Karachi')::date - 120", conn))
        {
            q.Parameters.AddWithValue("h", id);
            await using var r = await q.ExecuteReaderAsync();
            while (await r.ReadAsync()) days.Add(r.GetFieldValue<DateOnly>(0));
        }
        return $"habit done: {name}. Current streak: {Streak(days, TodayPk())} day(s)";
    }

    public static async Task<string> RemoveHabit(IConfiguration cfg, string match)
    {
        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        var (id, name, problem) = await PickHabit(conn, match);
        if (problem != null) return problem;
        await using var up = new NpgsqlCommand("update habits set active = false where id = @id", conn);
        up.Parameters.AddWithValue("id", id);
        await up.ExecuteNonQueryAsync();
        return "habit removed: " + name;
    }

    public static async Task<string> ListHabits(IConfiguration cfg)
    {
        var data = await HabitData(cfg);
        if (data.Count == 0) return "Abhi koi habit track nahi ho rahi.";
        var today = TodayPk();
        var sb = new StringBuilder();
        foreach (var h in data)
        {
            var wk = Enumerable.Range(0, 7).Count(i => h.days.Contains(today.AddDays(-i)));
            sb.AppendLine($"{h.name}: {(h.days.Contains(today) ? "DONE today" : "NOT done yet today")}, streak {Streak(h.days, today)} day(s), {wk}/7 this week");
        }
        return sb.ToString();
    }

    // ---- Mood ----
    public static async Task<string> LogMood(IConfiguration cfg, int score, string note)
    {
        if (score < 1 || score > 10) return "ERROR: score 1 se 10 ke beech hona chahiye";
        note = (note ?? "").Trim();
        if (note.Length > 200) note = note[..200];
        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        await using (var cmd = new NpgsqlCommand("insert into moods (score, note) values (@s, @n)", conn))
        {
            cmd.Parameters.AddWithValue("s", score);
            cmd.Parameters.AddWithValue("n", note);
            await cmd.ExecuteNonQueryAsync();
        }
        await using var q = new NpgsqlCommand("select coalesce(avg(score),0) from moods where created_at >= now() - interval '7 days'", conn);
        var avg = Convert.ToDouble(await q.ExecuteScalarAsync());
        return $"mood saved: {score}/10. 7-day average: {avg.ToString("0.0", CultureInfo.InvariantCulture)}";
    }

    // ---- Evening check-in ----
    public static async Task<string> EveningCheckin(IConfiguration cfg)
    {
        var sb = new StringBuilder();
        sb.AppendLine("TASKS DONE TODAY:");
        try { sb.AppendLine(Top(await Db.ListTasks(cfg, "done"), 8)); } catch { sb.AppendLine("(unavailable)"); }
        sb.AppendLine("TASKS STILL PENDING (top):");
        try { sb.AppendLine(Top(await Db.ListTasks(cfg, "pending"), 6)); } catch { sb.AppendLine("(unavailable)"); }
        sb.AppendLine("SPENT TODAY:");
        try { sb.AppendLine(Top(await ExpenseSummary(cfg, "today"), 8)); } catch { sb.AppendLine("(unavailable)"); }
        sb.AppendLine("HABITS:");
        try { sb.AppendLine(await ListHabits(cfg)); } catch { sb.AppendLine("(unavailable)"); }
        sb.AppendLine("MOOD LOGGED TODAY:");
        try
        {
            await using var conn = Conn(cfg);
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand(
                @"select score from moods
                  where (created_at at time zone 'Asia/Karachi')::date = (now() at time zone 'Asia/Karachi')::date
                  order by created_at desc limit 1", conn);
            var v = await cmd.ExecuteScalarAsync();
            sb.AppendLine(v == null ? "not yet" : Convert.ToInt32(v) + "/10");
        }
        catch { sb.AppendLine("(unavailable)"); }
        return sb.ToString();
    }

    // ---- Weekly review ----
    public static async Task<string> WeeklyReview(IConfiguration cfg)
    {
        var sb = new StringBuilder();
        sb.AppendLine("PERIOD: last 7 days (compare with the 7 days before)");

        try
        {
            await using var conn = Conn(cfg);
            await conn.OpenAsync();

            long done, pending, overdue;
            await using (var c1 = new NpgsqlCommand("select count(*) from tasks where done and done_at >= now() - interval '7 days'", conn))
                done = Convert.ToInt64(await c1.ExecuteScalarAsync());
            await using (var c2 = new NpgsqlCommand("select count(*) from tasks where not done", conn))
                pending = Convert.ToInt64(await c2.ExecuteScalarAsync());
            await using (var c3 = new NpgsqlCommand(
                "select count(*) from tasks where not done and due_date is not null and due_date < (now() at time zone 'Asia/Karachi')::date", conn))
                overdue = Convert.ToInt64(await c3.ExecuteScalarAsync());
            sb.AppendLine($"TASKS: {done} completed, {pending} still pending, {overdue} overdue");

            var titles = new List<string>();
            await using (var c4 = new NpgsqlCommand(
                "select title from tasks where done and done_at >= now() - interval '7 days' order by done_at desc limit 8", conn))
            await using (var r4 = await c4.ExecuteReaderAsync())
                while (await r4.ReadAsync()) titles.Add(r4.GetString(0));
            if (titles.Count > 0) sb.AppendLine("COMPLETED: " + string.Join("; ", titles));
        }
        catch { sb.AppendLine("TASKS: (unavailable)"); }

        try
        {
            sb.AppendLine("SPENDING THIS WEEK:");
            sb.AppendLine(Top(await ExpenseSummary(cfg, "week"), 8));
            await using var conn = Conn(cfg);
            await conn.OpenAsync();
            await using var cp = new NpgsqlCommand(
                "select coalesce(sum(amount),0) from expenses where spent_at >= now() - interval '14 days' and spent_at < now() - interval '7 days'", conn);
            var prev = Convert.ToDecimal(await cp.ExecuteScalarAsync());
            sb.AppendLine("SPENDING PREVIOUS WEEK TOTAL: " + M(prev));
        }
        catch { sb.AppendLine("SPENDING: (unavailable)"); }

        try
        {
            sb.AppendLine("HABITS:");
            sb.AppendLine(await ListHabits(cfg));
        }
        catch { sb.AppendLine("HABITS: (unavailable)"); }

        try
        {
            await using var conn = Conn(cfg);
            await conn.OpenAsync();
            var entries = new List<string>();
            await using (var cm = new NpgsqlCommand(
                @"select to_char(created_at at time zone 'Asia/Karachi','Dy DD'), score from moods
                  where created_at >= now() - interval '7 days' order by created_at", conn))
            await using (var rm = await cm.ExecuteReaderAsync())
                while (await rm.ReadAsync()) entries.Add(rm.GetString(0) + "=" + rm.GetInt32(1));

            double avgNow, avgPrev;
            await using (var ca = new NpgsqlCommand("select coalesce(avg(score),0) from moods where created_at >= now() - interval '7 days'", conn))
                avgNow = Convert.ToDouble(await ca.ExecuteScalarAsync());
            await using (var cb = new NpgsqlCommand(
                "select coalesce(avg(score),0) from moods where created_at >= now() - interval '14 days' and created_at < now() - interval '7 days'", conn))
                avgPrev = Convert.ToDouble(await cb.ExecuteScalarAsync());

            sb.AppendLine("MOOD: " + (entries.Count == 0 ? "no entries this week" : string.Join(", ", entries)));
            sb.AppendLine($"MOOD AVERAGE: this week {avgNow.ToString("0.0", CultureInfo.InvariantCulture)}, previous week {avgPrev.ToString("0.0", CultureInfo.InvariantCulture)} (0.0 means no data)");

            sb.AppendLine("WORK NOTES THIS WEEK:");
            int n = 0;
            await using (var cn = new NpgsqlCommand(
                @"select to_char(created_at at time zone 'Asia/Karachi','DD Mon'), command from command_logs
                  where command like 'NOTE:%' and created_at >= now() - interval '7 days' order by created_at desc limit 8", conn))
            await using (var rn = await cn.ExecuteReaderAsync())
                while (await rn.ReadAsync())
                {
                    n++;
                    sb.AppendLine(rn.GetString(0) + ": " + rn.GetString(1).Replace("NOTE:", "").Trim());
                }
            if (n == 0) sb.AppendLine("(none)");
        }
        catch { sb.AppendLine("MOOD/NOTES: (unavailable)"); }

        return sb.ToString();
    }

    // ---- Screen ke liye ----
    public static async Task<object> Snapshot(IConfiguration cfg)
    {
        try
        {
            var habits = await HabitData(cfg);
            var today = TodayPk();
            var hOut = habits.Select(h => new
            {
                name = h.name,
                doneToday = h.days.Contains(today),
                streak = Streak(h.days, today),
                week = Enumerable.Range(0, 7).Select(i => h.days.Contains(today.AddDays(i - 6))).ToArray()
            }).ToList();

            await using var conn = Conn(cfg);
            await conn.OpenAsync();
            var tToday = await Total(conn, "today");
            var tWeek = await Total(conn, "week");
            var tMonth = await Total(conn, "month");

            var cats = new List<object>();
            await using (var c1 = new NpgsqlCommand(
                "select category, sum(amount) from expenses where " + PeriodSql("month") + " group by category order by sum(amount) desc", conn))
            await using (var r1 = await c1.ExecuteReaderAsync())
                while (await r1.ReadAsync()) cats.Add(new { category = r1.GetString(0), total = r1.GetDecimal(1) });

            var recent = new List<object>();
            await using (var c2 = new NpgsqlCommand(
                @"select to_char(spent_at at time zone 'Asia/Karachi','DD Mon HH24:MI'), amount, category, coalesce(note,'')
                  from expenses order by spent_at desc limit 8", conn))
            await using (var r2 = await c2.ExecuteReaderAsync())
                while (await r2.ReadAsync())
                    recent.Add(new { when = r2.GetString(0), amount = r2.GetDecimal(1), category = r2.GetString(2), note = r2.GetString(3) });

            var moods = new List<object>();
            await using (var c3 = new NpgsqlCommand(
                @"select to_char(created_at at time zone 'Asia/Karachi','DD Mon'), score, coalesce(note,'')
                  from moods order by created_at desc limit 7", conn))
            await using (var r3 = await c3.ExecuteReaderAsync())
                while (await r3.ReadAsync())
                    moods.Add(new { day = r3.GetString(0), score = r3.GetInt32(1), note = r3.GetString(2) });

            return new
            {
                expenses = new { today = tToday, week = tWeek, month = tMonth, categories = cats, recent },
                habits = hOut,
                moods
            };
        }
        catch (Exception ex)
        {
            Console.WriteLine("LIFE ERROR: " + ex.Message);
            return new { error = ex.Message };
        }
    }
}

static class Db
{
    // Har connection par user ka id Postgres ko bata deta hai; RLS policies is se sirf us user ki rows dikhati hain.
    public static NpgsqlConnection NewConn(IConfiguration cfg)
    {
        var conn = new NpgsqlConnection(cfg.GetConnectionString("Supabase"));
        var uid = CurrentUser.Id.Value;
        if (uid != null)
            conn.StateChange += (sender, e) =>
            {
                if (e.CurrentState != System.Data.ConnectionState.Open) return;
                using var c = ((NpgsqlConnection)sender!).CreateCommand();
                c.CommandText = "select set_config('app.user_id', @u, false)";
                c.Parameters.AddWithValue("u", uid.Value.ToString());
                c.ExecuteNonQuery();
            };
        return conn;
    }

    static NpgsqlConnection Conn(IConfiguration cfg) => Db.NewConn(cfg);

    public static TimeZoneInfo Pk()
    {
        try { return TimeZoneInfo.FindSystemTimeZoneById("Pakistan Standard Time"); }
        catch { return TimeZoneInfo.CreateCustomTimeZone("PKT", TimeSpan.FromHours(5), "PKT", "PKT"); }
    }

    static DateOnly TodayPk() => DateOnly.FromDateTime(TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, Pk()));

    public static async Task<List<MemoryItem>> GetMemories(IConfiguration cfg)
    {
        var list = new List<MemoryItem>();
        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand("select id, content from memories order by created_at desc limit 200", conn);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync()) list.Add(new MemoryItem(r.GetGuid(0), r.GetString(1)));
        return list;
    }

    public static async Task SaveMemory(IConfiguration cfg, string content)
    {
        try
        {
            await using var conn = Conn(cfg);
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand(
                "insert into memories (content) select @c where not exists (select 1 from memories where lower(content) = lower(@c))", conn);
            cmd.Parameters.AddWithValue("c", content);
            await cmd.ExecuteNonQueryAsync();
        }
        catch { }
    }

    public static async Task DeleteMemory(IConfiguration cfg, Guid id)
    {
        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand("delete from memories where id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    public static async Task Log(IConfiguration cfg, string command, string result)
    {
        try
        {
            await using var conn = Conn(cfg);
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand(
                "insert into command_logs (command, status, result) values (@c, 'done', @r)", conn);
            cmd.Parameters.AddWithValue("c", command);
            cmd.Parameters.AddWithValue("r", result.Length > 500 ? result[..500] : result);
            await cmd.ExecuteNonQueryAsync();
        }
        catch { }
    }

    public static async Task<string> TodayLog(IConfiguration cfg)
    {
        var sb = new StringBuilder();
        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            @"select to_char(created_at at time zone 'Asia/Karachi', 'HH24:MI'), command, coalesce(result,'')
              from command_logs
              where (created_at at time zone 'Asia/Karachi')::date = (now() at time zone 'Asia/Karachi')::date
              order by created_at", conn);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync()) sb.AppendLine($"{r.GetString(0)} | {r.GetString(1)} | {r.GetString(2)}");
        return sb.Length == 0 ? "Aaj ka koi record nahi." : sb.ToString();
    }

    // ---- Reminders ----
    public static async Task AddReminder(IConfiguration cfg, string text, DateTime dueUtc)
    {
        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand("insert into reminders (text, due_at) values (@t, @d)", conn);
        cmd.Parameters.AddWithValue("t", text);
        cmd.Parameters.AddWithValue("d", dueUtc);
        await cmd.ExecuteNonQueryAsync();
    }

    public static async Task<List<string>> TakeDue(IConfiguration cfg)
    {
        var list = new List<string>();
        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            "update reminders set done = true where done = false and due_at <= now() returning text", conn);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync()) list.Add(r.GetString(0));
        return list;
    }

    public static async Task<string> ListReminders(IConfiguration cfg)
    {
        var sb = new StringBuilder();
        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            @"select to_char(due_at at time zone 'Asia/Karachi', 'DD Mon HH24:MI'), text
              from reminders where done = false order by due_at", conn);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync()) sb.AppendLine($"{r.GetString(0)} | {r.GetString(1)}");
        return sb.Length == 0 ? "Koi pending reminder nahi." : sb.ToString();
    }

    public static async Task<int> ClearReminders(IConfiguration cfg)
    {
        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand("update reminders set done = true where done = false", conn);
        return await cmd.ExecuteNonQueryAsync();
    }

    // ---- Tasks ----
    public static async Task AddTask(IConfiguration cfg, string title, DateOnly? due, int priority)
    {
        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand("insert into tasks (title, due_date, priority) values (@t, @d, @p)", conn);
        cmd.Parameters.AddWithValue("t", title);
        cmd.Parameters.Add(new NpgsqlParameter("d", NpgsqlTypes.NpgsqlDbType.Date) { Value = (object?)due ?? DBNull.Value });
        cmd.Parameters.AddWithValue("p", priority);
        await cmd.ExecuteNonQueryAsync();
    }

    static string DueText(DateOnly? due, DateOnly today)
    {
        if (due == null) return "no date";
        var d = due.Value;
        if (d < today) return "OVERDUE since " + d.ToString("dd MMM");
        if (d == today) return "due today";
        if (d == today.AddDays(1)) return "due tomorrow";
        return "due " + d.ToString("ddd dd MMM");
    }

    public static async Task<string> ListTasks(IConfiguration cfg, string filter)
    {
        filter = string.IsNullOrWhiteSpace(filter) ? "pending" : filter.ToLower().Trim();
        var today = TodayPk();
        string sql;
        if (filter == "done")
            sql = @"select title, due_date, priority from tasks
                    where done = true and (done_at at time zone 'Asia/Karachi')::date = (now() at time zone 'Asia/Karachi')::date
                    order by done_at";
        else if (filter == "today")
            sql = @"select title, due_date, priority from tasks
                    where done = false and due_date is not null and due_date <= (now() at time zone 'Asia/Karachi')::date
                    order by due_date, priority desc";
        else
            sql = @"select title, due_date, priority from tasks where done = false
                    order by (due_date is null), due_date, priority desc, created_at";

        var sb = new StringBuilder();
        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, conn);
        await using var r = await cmd.ExecuteReaderAsync();
        int n = 0;
        while (await r.ReadAsync())
        {
            n++;
            DateOnly? due = r.IsDBNull(1) ? null : r.GetFieldValue<DateOnly>(1);
            var pri = r.GetInt32(2);
            var extra = pri >= 3 ? ", high priority" : pri <= 1 ? ", low priority" : "";
            sb.AppendLine($"{n}. {r.GetString(0)} ({DueText(due, today)}{extra})");
        }
        if (sb.Length == 0)
            return filter == "done" ? "Aaj koi task complete nahi hua." : filter == "today" ? "Aaj ke liye koi task nahi." : "Koi pending task nahi.";
        return sb.ToString();
    }

    public static async Task<string> CompleteTask(IConfiguration cfg, string match)
    {
        match = (match ?? "").Trim();
        if (match.Length == 0) return "ERROR: kaunsa task? kuch lafz batayein";
        await using var conn = Conn(cfg);
        await conn.OpenAsync();

        var found = new List<(Guid id, string title)>();
        await using (var cmd = new NpgsqlCommand(
            "select id, title from tasks where done = false and title ilike @m order by created_at limit 6", conn))
        {
            cmd.Parameters.AddWithValue("m", "%" + match.Replace("%", "").Replace("_", "") + "%");
            await using var r = await cmd.ExecuteReaderAsync();
            while (await r.ReadAsync()) found.Add((r.GetGuid(0), r.GetString(1)));
        }

        if (found.Count == 0) return "NOT FOUND: koi pending task '" + match + "' se match nahi hua";
        var pick = found.Count == 1
            ? found[0]
            : found.FirstOrDefault(x => x.title.Equals(match, StringComparison.OrdinalIgnoreCase));
        if (pick.title == null)
            return "AMBIGUOUS: kai tasks match hue: " + string.Join(" | ", found.Select(x => x.title)) + ". Ek ko poora naam bolkar batayein.";

        await using var up = new NpgsqlCommand("update tasks set done = true, done_at = now() where id = @id", conn);
        up.Parameters.AddWithValue("id", pick.id);
        await up.ExecuteNonQueryAsync();
        return "completed: " + pick.title;
    }

    // ---- Notes ----
    public static async Task AddNote(IConfiguration cfg, string content, string tag)
    {
        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand("insert into notes (content, tag) values (@c, @t)", conn);
        cmd.Parameters.AddWithValue("c", content);
        cmd.Parameters.AddWithValue("t", string.IsNullOrWhiteSpace(tag) ? "general" : tag.Trim().ToLower());
        await cmd.ExecuteNonQueryAsync();
    }

    public static async Task<string> SearchNotes(IConfiguration cfg, string query)
    {
        query = (query ?? "").Trim();
        var sb = new StringBuilder();
        await using var conn = Conn(cfg);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            @"select to_char(created_at at time zone 'Asia/Karachi', 'DD Mon HH24:MI'), content, coalesce(tag,'')
              from notes
              where @q = '' or content ilike @p or tag ilike @p
              order by created_at desc limit 10", conn);
        cmd.Parameters.AddWithValue("q", query);
        cmd.Parameters.AddWithValue("p", "%" + query.Replace("%", "").Replace("_", "") + "%");
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
            sb.AppendLine($"{r.GetString(0)} [{r.GetString(2)}] {r.GetString(1)}");
        return sb.Length == 0 ? "Koi note nahi mila." : sb.ToString();
    }

    // ---- Subah ki briefing ka data ----
    public static async Task<string> Briefing(IConfiguration cfg)
    {
        var nowPk = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, Pk());
        var sb = new StringBuilder();
        sb.AppendLine("NOW: " + nowPk.ToString("dddd, dd MMM yyyy HH:mm"));
        sb.AppendLine("PENDING TASKS:");
        try { sb.AppendLine(await ListTasks(cfg, "pending")); } catch (Exception ex) { sb.AppendLine("(tasks unavailable: " + ex.Message + ")"); }
        sb.AppendLine("PENDING REMINDERS:");
        try { sb.AppendLine(await ListReminders(cfg)); } catch { sb.AppendLine("(reminders unavailable)"); }
        sb.AppendLine("RECENT WORK NOTES (last 2 days):");
        try
        {
            await using var conn = Conn(cfg);
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand(
                @"select to_char(created_at at time zone 'Asia/Karachi','DD Mon'), command
                  from command_logs
                  where command like 'NOTE:%' and created_at > now() - interval '2 days'
                  order by created_at desc limit 6", conn);
            await using var r = await cmd.ExecuteReaderAsync();
            int n = 0;
            while (await r.ReadAsync())
            {
                n++;
                sb.AppendLine($"{r.GetString(0)}: {r.GetString(1).Replace("NOTE:", "").Trim()}");
            }
            if (n == 0) sb.AppendLine("(none)");
        }
        catch { sb.AppendLine("(unavailable)"); }
        return sb.ToString();
    }
}static class PhoneBridge
{
    public static readonly AsyncLocal<List<object>?> Out = new();

    public const string Hint = """


        PHONE MODE:
        - The user is talking to you from their Android phone app, not from the PC. "Phone" means the user's phone.
        - To open phone apps, dial numbers, write SMS, use the flashlight, set alarms or timers, change phone volume, navigate or open phone settings, use the phone_* tools.
        - If the user says open WhatsApp, YouTube, Camera, Chrome and so on without saying PC or computer, use phone_open_app. To search on YouTube use phone_open_url with a YouTube search address.
        - The PC tools (open_app, shutdown_pc, volume, media and the rest) act on the user's PC at home. Use them only when the user clearly says PC or computer.
        - phone_call and phone_sms only open the dialer or the message screen. Tell the user in a few words that they must press the button themselves.
        - Phone tools cannot tell you whether the app exists. The phone will report a problem itself, so just confirm briefly.
        """;

    public static string Send(string name, JsonElement a)
    {
        var list = Out.Value;
        if (list == null) return "ERROR: ye command sirf phone app se chalti hai";
        var args = a.ValueKind == JsonValueKind.Object ? a.Clone() : JsonDocument.Parse("{}").RootElement.Clone();
        list.Add(new { t = "phone", name, args });
        return "sent to the phone";
    }
}