// NestJS controllers: one unguarded admin delete, one guarded resource controller.
import { Controller, Delete, Get, Param, UseGuards } from '@nestjs/common'
import { AuthGuard } from '@nestjs/passport'
import { RolesGuard } from './roles.guard'

@Controller('admin')
export class AdminController {
  constructor (private readonly userRepository: any) {}

  @Delete('users/:id')
  removeUser (@Param('id') id: string) {
    return this.userRepository.delete(id)
  }
}

@Controller('orders')
@UseGuards(AuthGuard('jwt'))
export class OrdersController {
  constructor (private readonly orderRepository: any) {}

  @Get(':id')
  findOne (@Param('id') id: string) {
    return this.orderRepository.findOneBy({ id })
  }
}

@Controller('reports')
@UseGuards(AuthGuard('jwt'), RolesGuard)
export class ReportsController {
  constructor (private readonly reportRepository: any) {}

  @Delete(':id')
  remove (@Param('id') id: string) {
    return this.reportRepository.delete(id)
  }
}
