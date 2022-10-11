import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';

import { Model } from 'mongoose';

import { CreateUserDto, UpdateUserDto } from './dto/createUserDto';
import { User, UserDocument } from './schemas/user.schema';

@Injectable()
export class UserService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  async findAll(): Promise<UserDocument[]> {
    return this.userModel.find().exec();
  }

  async findByEmail(email: string): Promise<UserDocument> {
    return await this.userModel.findOne({ email }).select('+password').exec();
  }

  async findById(
    id: string,
    { refreshToken }: { refreshToken?: boolean } = {},
  ): Promise<UserDocument> {
    return this.userModel
      .findById(id)
      .select(refreshToken && '+refreshToken')
      .exec();
  }

  async create(createUserDto: CreateUserDto): Promise<UserDocument> {
    return this.userModel.create({ ...createUserDto, createdAt: new Date() });
  }

  async update(
    id: string,
    updateUserDto: UpdateUserDto,
  ): Promise<UserDocument> {
    return this.userModel
      .findByIdAndUpdate(id, updateUserDto, { new: true })
      .exec();
  }

  async updateRefreshToken(id: string, refreshToken: string | null) {
    return this.userModel
      .findByIdAndUpdate(id, { refreshToken }, { new: true })
      .exec();
  }
}
