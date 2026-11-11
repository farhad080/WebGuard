// DOM XSS through a class field: the query param is stored on `this.searchValue` in one
// lifecycle hook and written with innerHTML in another.
import { Component, ElementRef, type AfterViewInit, type OnInit } from '@angular/core'
import { ActivatedRoute } from '@angular/router'

@Component({ selector: 'app-search-box', template: '<div id="searchValue"></div>' })
export class SearchBoxComponent implements OnInit, AfterViewInit {
  public searchValue = ''

  constructor (private readonly route: ActivatedRoute, private readonly el: ElementRef) {}

  ngOnInit () {
    const queryParam: string = this.route.snapshot.queryParams.q
    this.searchValue = queryParam ? queryParam.trim() : ''
  }

  ngAfterViewInit () {
    const box = this.el.nativeElement.querySelector('#searchValue')
    box.innerHTML = this.searchValue
  }
}
