// Mirrors Juice Shop frontend/src/app/track-result/track-result.component.ts
// (challenge #28 Reflected XSS: the order id from the URL comes back in the API response)
import { Component, type OnInit } from '@angular/core'
import { ActivatedRoute } from '@angular/router'
import { DomSanitizer } from '@angular/platform-browser'
import { TrackOrderService } from '../Services/track-order.service'

@Component({ selector: 'app-track-result', templateUrl: './track-result.component.html' })
export class TrackResultComponent implements OnInit {
  public orderId?: string
  public results: any = {}

  constructor (private readonly route: ActivatedRoute, private readonly trackOrderService: TrackOrderService, private readonly sanitizer: DomSanitizer) {}

  ngOnInit () {
    this.orderId = this.route.snapshot.queryParams.id
    this.trackOrderService.find(this.orderId).subscribe((results) => {
      this.results.orderNo = this.sanitizer.bypassSecurityTrustHtml(`<code>${results.data[0].orderId}</code>`)
    })
  }
}
