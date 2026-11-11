// Mirrors Juice Shop frontend/src/app/search-result/search-result.component.ts
// (challenges #26/#27 DOM XSS via the search param, #29 API-only XSS via product descriptions)
import { Component, type OnInit } from '@angular/core'
import { ActivatedRoute } from '@angular/router'
import { DomSanitizer } from '@angular/platform-browser'
import { ProductService } from '../Services/product.service'

@Component({ selector: 'app-search-result', templateUrl: './search-result.component.html' })
export class SearchResultComponent implements OnInit {
  public searchValue?: any
  public tableData!: any[]

  constructor (private readonly route: ActivatedRoute, private readonly sanitizer: DomSanitizer, private readonly productService: ProductService) {}

  ngOnInit () {
    this.productService.search('').subscribe((tableData: any) => {
      this.tableData = tableData
      for (let i = 0; i < tableData.length; i++) {
        tableData[i].description = this.sanitizer.bypassSecurityTrustHtml(tableData[i].description)
      }
      this.filterTable()
    })
  }

  filterTable () {
    let queryParam: string = this.route.snapshot.queryParams.q
    if (queryParam) {
      queryParam = queryParam.trim()
      this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)
    }
  }
}
