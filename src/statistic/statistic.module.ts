import { Module } from '@nestjs/common';
import { StatisticService } from './statistic.service';
import { StatisticController } from './statistic.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Booking } from 'src/booking/entities/booking.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Booking])],
  providers: [StatisticService],
  controllers: [StatisticController],
})
export class StatisticModule {}
