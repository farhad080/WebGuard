// Mirrors Juice Shop frontend/src/app/administration/administration.component.ts
// (challenge #30 Client-side XSS Protection: a stored email renders in the admin user list)
import { Component } from '@angular/core'
import { DomSanitizer } from '@angular/platform-browser'
import { UserService } from '../Services/user.service'

@Component({ selector: 'app-administration', templateUrl: './administration.component.html' })
export class AdministrationComponent {
  public userDataSource: any[] = []

  constructor (private readonly userService: UserService, private readonly sanitizer: DomSanitizer) {}

  findAllUsers () {
    this.userService.find().subscribe((users) => {
      this.userDataSource = users
      for (const user of this.userDataSource) {
        user.email = this.sanitizer.bypassSecurityTrustHtml(`<span class="${this.doesUserHaveAnActiveSession(user) ? 'confirmation' : 'error'}">${user.email}</span>`)
      }
    })
  }

  doesUserHaveAnActiveSession (user: { email: string }) {
    return user.email.length > 0
  }
}
