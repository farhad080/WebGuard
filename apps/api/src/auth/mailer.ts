/**
 * Outgoing mail for account flows. WebGuard ships no email transport yet: the default
 * `ConsoleMailer` prints the reset link to the server log in development only (never in
 * production, where it logs that delivery is not configured). Plug in an SMTP/SES mailer by
 * implementing `Mailer` and passing it to `setMailer()`.
 */
export interface Mailer {
  sendPasswordReset(to: string, resetUrl: string): Promise<void>;
}

export class ConsoleMailer implements Mailer {
  async sendPasswordReset(to: string, resetUrl: string): Promise<void> {
    if (process.env.NODE_ENV === 'production') {
      console.warn('[mailer] password reset requested but no mail transport is configured');
      return;
    }
    console.log(`[mailer:dev] password reset for ${to}: ${resetUrl}`);
  }
}

let mailer: Mailer = new ConsoleMailer();

export function getMailer(): Mailer {
  return mailer;
}

export function setMailer(next: Mailer): void {
  mailer = next;
}
