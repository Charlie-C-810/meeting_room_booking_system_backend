import { Module } from '@nestjs/common';
import { BookingService } from './booking.service';
import { BookingController } from './booking.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Booking } from './entities/booking.entity';
import { RedisModule } from 'src/redis/redis.module';
import { EmailModule } from 'src/email/email.module';

@Module({
  imports: [TypeOrmModule.forFeature([Booking]), RedisModule, EmailModule],
  controllers: [BookingController],
  providers: [BookingService],
})
export class BookingModule {}
