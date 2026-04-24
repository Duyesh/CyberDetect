// Simple auth simulation

function checkAuthHeuristics(senderEmail, replyTo, links) {

    const result = {
        spfFail: false,
        dmarcFail: false
    };

    if (!senderEmail || !senderEmail.includes("@")) return result;

    const senderDomain = senderEmail.split("@")[1];

    // SPF simulation → links should match sender domain
    links.forEach(link => {
        try {
            const linkDomain = new URL(link).hostname;

            if (!linkDomain.includes(senderDomain)) {
                result.spfFail = true;
            }
        } catch {}
    });

    // DMARC simulation → reply-to mismatch
    if (replyTo && !replyTo.includes(senderDomain)) {
        result.dmarcFail = true;
    }

    return result;
}