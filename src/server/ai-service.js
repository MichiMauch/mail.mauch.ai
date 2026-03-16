/**
 * ╔══════════════════════════════════════════════════════════╗
 *  AI-SERVICE
 *  Generiert E-Mail-Antworten basierend auf Kontext
 *  und Benutzer-Anweisungen via OpenAI Responses API
 * ╚══════════════════════════════════════════════════════════╝
 */

import OpenAI from 'openai';

const SYSTEM_PROMPT = `Du bist ein professioneller E-Mail-Assistent. Du schreibst E-Mail-Antworten auf Deutsch (Schweizer Hochdeutsch, kein Dialekt).

Regeln:
- Schreibe NUR den E-Mail-Body (kein Betreff, kein "Von:", kein "An:")
- Beginne direkt mit der Anrede (z.B. "Guten Tag Frau Müller," oder "Lieber Max,")
- Schliesse mit einem passenden Gruss (z.B. "Freundliche Grüsse" + Zeilenumbruch, OHNE Namen – den fügt der User selbst hinzu)
- Halte den Ton professionell aber freundlich
- Sei prägnant – nicht zu lang, nicht zu kurz
- Verwende keine Emojis in formellen Mails
- Wenn der Kontext informell ist (Freunde, Familie), passe den Ton an
- Beantworte die Mail basierend auf den Stichpunkten/Anweisungen des Users
- Berücksichtige den Inhalt der Original-Mail für eine kontextbezogene Antwort
- Gib NUR den reinen E-Mail-Text zurück, keine Erklärungen oder Kommentare`;

export class AIService {
  constructor(apiKey) {
    if (!apiKey) throw new Error('OPENAI_API_KEY nicht konfiguriert');
    this.client = new OpenAI({ apiKey });
    this.model = process.env.AI_MODEL || 'gpt-4o-mini';
  }

  /**
   * Generiert eine E-Mail-Antwort
   */
  async generateReply({ originalFrom, originalSubject, originalBody, instructions, userName }) {
    const maxBodyLength = 3000;
    const trimmedBody = originalBody && originalBody.length > maxBodyLength
      ? originalBody.slice(0, maxBodyLength) + '\n[... gekürzt]'
      : originalBody || '(kein Text)';

    const input = `Original-Mail:
Von: ${originalFrom || 'Unbekannt'}
Betreff: ${originalSubject || '(kein Betreff)'}
Inhalt:
${trimmedBody}

---

Meine Anweisungen für die Antwort:
${instructions}

${userName ? `(Mein Name: ${userName})` : ''}`;

    const response = await this.client.responses.create({
      model: this.model,
      instructions: SYSTEM_PROMPT,
      input,
    });

    const text = response.output_text || '';
    console.log(`[AI] Antwort generiert (${text.length} Zeichen)`);
    return text;
  }

  /**
   * Generiert eine neue E-Mail (kein Reply-Kontext)
   */
  async generateNew({ instructions, recipient, userName }) {
    const input = `Schreibe eine neue E-Mail.

Empfänger: ${recipient || '(nicht angegeben)'}

Anweisungen:
${instructions}

${userName ? `(Mein Name: ${userName})` : ''}`;

    const response = await this.client.responses.create({
      model: this.model,
      instructions: SYSTEM_PROMPT,
      input,
    });

    const text = response.output_text || '';
    console.log(`[AI] Neue Mail generiert (${text.length} Zeichen)`);
    return text;
  }
}
