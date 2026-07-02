console.log("DNS CHECKER LOADED");

function getDomain(url) {
    try {
        return new URL(url).hostname.toLowerCase();
    } catch {
        return null;
    }
}

async function checkDNS(url) {
    const domain = getDomain(url);

    if (!domain) {
        return { status: "safe", score: 100, flags: [] };
    }

    // STEP 1: @ symbol = instant phishing
    if (url.includes("@")) {
        return { status: "spoofed", score: 5, flags: ["@ symbol found in URL — classic phishing pattern"] };
    }

    try {
        // STEP 2: Real DNS lookup via Google DNS-over-HTTPS
        let data;

        try {
            const response = await fetch(
                `https://dns.google/resolve?name=${domain}&type=A`
            );

            if (!response.ok) {
                throw new Error("DNS fetch failed");
            }

            data = await response.json();

        } catch (err) {
            console.error("DNS FETCH FAILED:", err);

            return {
                status: "safe",
                score: 80,
                flags: ["DNS lookup failed"]
            };
        }

        let flags = [];
        let anomalyScore = 0;

        // RULE 1: Domain does not resolve at all
        if (!data.Answer || data.Answer.length === 0) {
            flags.push("No A records found — domain does not exist");
            return { status: "spoofed", score: 5, flags };
        }

        const aRecords = (data.Answer || []).filter(r => r.type === 1);
        const ips = aRecords.map(r => r.data);
        const ttl = aRecords.length ? aRecords[0].TTL : 0;

        // RULE 2: Very low TTL — cache poisoning signal
        if (ttl > 0 && ttl < 300) {
            anomalyScore += 0.3;
            flags.push(`Suspiciously low TTL: ${ttl}s — possible DNS cache poisoning`);
        }

        // RULE 3: Private/loopback IP returned for public domain
        const hasPrivateIP = ips.some(ip =>
            ip.startsWith("127.") ||
            ip.startsWith("10.") ||
            ip.startsWith("192.168.") ||
            ip.startsWith("169.254.") ||
            ip === "0.0.0.0"
        );
        if (hasPrivateIP) {
            anomalyScore += 0.5;
            flags.push("Private IP in DNS response — possible DNS hijacking");
        }

        // RULE 4: Too many IPs
        if (ips.length > 5) {
            anomalyScore += 0.25;
            flags.push(`Excessive IP count: ${ips.length} addresses returned`);
        }

        // RULE 5: Suspicious keyword + hyphen in domain
        if (
            (domain.includes("login") ||
             domain.includes("secure") ||
             domain.includes("verify") ||
             domain.includes("update") ||
             domain.includes("confirm")) &&
            domain.includes("-")
        ) {
            anomalyScore += 0.3;
            flags.push("Suspicious keyword + hyphen in domain name");
        }

        // Final score calculation
        const finalScore = Math.min(anomalyScore, 1.0);

        let status = "safe";
        if (finalScore >= 0.5) status = "spoofed";
        else if (finalScore >= 0.25) status = "suspicious";

        return {
            status,
            score: Math.round((1 - finalScore) * 100),
            flags,
            ips,
            ttl
        };

    } catch (err) {
        console.error("DNS lookup error:", err);
        return { status: "safe", score: 80, flags: ["DNS lookup could not be completed"] };
    }
}