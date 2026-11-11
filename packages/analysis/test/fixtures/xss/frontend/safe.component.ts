// SAFE: textContent, DOMPurify, Angular's own sanitizer, static HTML, and auto-escaped
// template bindings ({{ value }}, plain [innerHTML] without a bypass). No findings.
import { Component, ElementRef, SecurityContext, type OnInit } from '@angular/core'
import { ActivatedRoute } from '@angular/router'
import { DomSanitizer } from '@angular/platform-browser'
import DOMPurify from 'dompurify'

@Component({ selector: 'app-safe', templateUrl: './safe.component.html' })
export class SafeComponent implements OnInit {
  public value = ''
  public html = ''

  constructor (private readonly route: ActivatedRoute, private readonly el: ElementRef, private readonly sanitizer: DomSanitizer) {}

  ngOnInit () {
    this.value = this.route.snapshot.queryParams.q
    this.html = this.route.snapshot.queryParams.html
    const box = this.el.nativeElement.querySelector('#out')
    box.textContent = this.value
    box.innerHTML = DOMPurify.sanitize(this.value)
    box.innerHTML = '<b>static</b>'
    const clean = this.sanitizer.sanitize(SecurityContext.HTML, this.html)
    box.insertAdjacentHTML('beforeend', clean)
  }
}
