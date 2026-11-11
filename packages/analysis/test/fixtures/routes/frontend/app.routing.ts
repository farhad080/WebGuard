// Juice Shop #20: the admin page is "protected" only by a client-side route guard.
import { type Routes } from '@angular/router'
import { AdministrationComponent } from './administration/administration.component'
import { AdminGuard } from './app.guard'

export const routes: Routes = [
  { path: 'administration', component: AdministrationComponent, canActivate: [AdminGuard] }
]
