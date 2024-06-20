import {
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { RegisterUserDto } from './user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import { RedisService } from 'src/redis/redis.service';
import { md5 } from 'src/utils';
import { Role } from './entities/role.entity';
import { Permission } from './entities/permissions.entity';
import { LoginUserDto } from './dto/login-user.dto';
import { LoginUserVo } from './vo/login-user.vo';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { UpdateUserPasswordDto } from './dto/update-user-password.dto';
import { UpdateUserDto } from './vo/udpate-user.dto';

@Injectable()
export class UserService {
  private logger = new Logger();

  /**
   * 通过@Inject装饰器注入RedisService实例。
   * 这使得当前类可以使用redisService实例来访问Redis服务。
   * 注入的RedisService用于处理与Redis数据库的相关操作。
   */
  @Inject(RedisService) private redisService: RedisService;
  @Inject(JwtService) private jwtService: JwtService;
  @Inject(ConfigService) private configService: ConfigService;
  /**
   * 通过@InjectRepository注解将userRepository注入到类中，
   * 使其能够方便地进行数据库操作，如查询、插入、更新和删除用户信息。
   * @type {Repository<User>} userRepository - 用户信息的数据库仓库，提供CRUD操作方法。
   */
  @InjectRepository(User) private userRepository: Repository<User>;
  @InjectRepository(Role) private roleRepository: Repository<Role>;
  @InjectRepository(Permission)
  private permissionRepository: Repository<Permission>;

  /**
   * 异步注册新用户。
   *
   * 此方法首先验证用户提供的邮箱验证码是否有效，然后检查用户名是否已被占用。
   * 如果验证通过，将创建一个新的用户对象并保存到数据库中。
   *
   * @param user 包含注册信息的数据传输对象，包括用户名、密码、邮箱和验证码。
   * @returns 返回注册结果的字符串，成功时为“注册成功”，失败时为“注册失败”。
   * @throws 如果验证码无效或已过期、用户名已存在或其他错误发生，则抛出HttpException。
   */
  async register(user: RegisterUserDto) {
    // 从Redis服务中获取用户邮箱对应的验证码
    const captcha = await this.redisService.get(`captcha_${user.email}`);

    // 验证验证码是否存在，如果不存在则抛出异常
    if (!captcha) {
      throw new HttpException('验证码已过期', HttpStatus.BAD_REQUEST);
    }

    // 验证用户输入的验证码与存储的验证码是否一致，不一致则抛出异常
    if (user.captcha !== captcha) {
      throw new HttpException('验证码不正确', HttpStatus.BAD_REQUEST);
    }

    // 检查用户名是否已被注册，如果已存在则抛出异常
    const foundUser = await this.userRepository.findOneBy({
      username: user.username,
    });
    if (foundUser) {
      throw new HttpException('用户名已存在', HttpStatus.BAD_REQUEST);
    }

    // 创建新的用户对象，并初始化属性
    const newUser = new User();
    newUser.username = user.username;
    newUser.password = md5(user.password); // 对密码进行MD5加密
    newUser.email = user.email;
    newUser.nickName = user.nickName;

    try {
      // 尝试保存新用户到数据库，如果成功则返回“注册成功”，否则捕获异常
      await this.userRepository.save(newUser);
      return '注册成功';
    } catch (e) {
      this.logger.error(e, UserService); // 记录注册失败的错误日志
      return '注册失败';
    }
  }

  /**
   * 异步登录方法。
   * 该方法通过用户名和密码验证用户身份，并返回通过验证的用户对象。
   * 如果用户不存在或密码不正确，将抛出Http异常。
   *
   * @param loginUserDto 登录用户的数据传输对象，包含用户名和密码。
   * @param isAdmin 指示是否为管理员用户，用于精细查询用户。
   * @returns 返回通过验证的用户对象。
   * @throws 如果用户不存在或密码不正确，抛出HTTP异常。
   */
  async login(loginUserDto: LoginUserDto, isAdmin: boolean) {
    // 根据用户名、是否为管理员和关联的角色与权限信息，查询用户。
    const user = await this.userRepository.findOne({
      where: {
        username: loginUserDto.username,
        isAdmin,
      },
      relations: ['roles', 'roles.permissions'],
    });
    // 如果用户不存在，则抛出“用户不存在”的HTTP异常。
    if (!user) {
      throw new HttpException('用户不存在', HttpStatus.BAD_REQUEST);
    }

    // 如果用户密码不匹配，则抛出“密码错误”的HTTP异常。
    if (user.password !== md5(loginUserDto.password)) {
      throw new HttpException('密码错误', HttpStatus.BAD_REQUEST);
    }
    // 返回验证通过的用户对象。
    const vo = new LoginUserVo();
    vo.userInfo = {
      id: user.id,
      username: user.username,
      nickName: user.nickName,
      email: user.email,
      phoneNumber: user.phoneNumber,
      headPic: user.headPic,
      createTime: user.createTime.getTime(),
      isFrozen: user.isFrozen,
      isAdmin: user.isAdmin,
      roles: user.roles.map((item) => item.name),
      permissions: user.roles.reduce((arr, item) => {
        item.permissions.forEach((permission) => {
          if (arr.indexOf(permission) === -1) {
            arr.push(permission);
          }
        });
        return arr;
      }, []),
    };

    this.generateToken(vo);
    return vo;
  }

  /**
   * 根据用户ID和是否为管理员身份异步查找用户。
   * 此方法通过查询用户仓库来获取用户信息，并包括其角色和权限。
   * @param userId 用户的唯一标识符。
   * @param isAdmin 指示是否为管理员的布尔值。这用于限制获取管理员特定的数据。
   * @returns 返回一个包含用户基本信息、角色和权限的对象。
   */
  async findUserById(userId: number, isAdmin: boolean) {
    // 根据用户ID和isAdmin查询用户，包括其角色和角色的权限。
    const user = await this.userRepository.findOne({
      where: {
        id: userId,
        isAdmin,
      },
      relations: ['roles', 'roles.permissions'],
    });
    // 构建并返回一个精简的用户对象，包括用户ID、用户名、是否为管理员、角色名称和权限。
    return {
      id: user.id,
      username: user.username,
      isAdmin: user.isAdmin,
      roles: user.roles.map((item) => item.name), // 提取角色名称列表
      permissions: user.roles.reduce((arr, item) => {
        item.permissions.forEach((permission) => {
          // 确保每个权限只出现一次，避免重复。
          if (arr.indexOf(permission) === -1) {
            arr.push(permission);
          }
        });
        return arr;
      }, []),
    };
  }

  generateToken(vo: LoginUserVo) {
    // 生成访问令牌。使用jsonwebtoken库，将用户ID、用户名、角色和权限等信息加密，并设置令牌的过期时间。
    vo.accessToken = this.jwtService.sign(
      {
        userId: vo.userInfo.id,
        username: vo.userInfo.username,
        roles: vo.userInfo.roles,
        permissions: vo.userInfo.permissions,
      },
      {
        expiresIn:
          this.configService.get('jwt_access_token_expires_time') || '30m',
      },
    );

    // 生成刷新令牌。与访问令牌不同的是，刷新令牌只包含用户ID，且过期时间更长。
    vo.refreshToken = this.jwtService.sign(
      {
        userId: vo.userInfo.id,
      },
      {
        expiresIn:
          this.configService.get('jwt_refresh_token_expres_time') || '7d',
      },
    );

    return vo;
  }

  async refresh(refreshToken: string, isAdmin: boolean) {
    try {
      // 使用JWT服务验证刷新令牌的有效性，并提取用户ID。
      const data = this.jwtService.verify(refreshToken);
      // 根据用户ID查找用户，确保用户存在且未被禁用。
      const user = await this.findUserById(data.userId, isAdmin);
      // 生成新的访问令牌，包含用户的ID、用户名、角色和权限信息。
      const access_token = this.jwtService.sign(
        {
          userId: user.id,
          username: user.username,
          roles: user.roles,
          permissions: user.permissions,
        },
        {
          expiresIn:
            this.configService.get('jwt_access_token_expires_time') || '30m',
        },
      );
      // 生成新的刷新令牌，包含用户的ID。
      const refresh_token = this.jwtService.sign(
        {
          userId: user.id,
        },
        {
          expiresIn:
            this.configService.get('jwt_refresh_token_expres_time') || '7d',
        },
      );
      // 返回新的访问令牌和刷新令牌。
      return {
        access_token,
        refresh_token,
      };
    } catch (error) {
      // 如果在令牌验证或生成过程中出现错误，抛出未授权异常。
      throw new UnauthorizedException('token 已失效，请重新登录');
    }
  }

  async findUserDetailById(userId: number) {
    const user = await this.userRepository.findOne({
      where: {
        id: userId,
      },
    });

    return user;
  }

  /**
   * 异步更新用户密码。
   *
   * 此方法首先验证用户提供的验证码是否有效，然后更新用户的密码。
   * 它通过检查Redis中存储的验证码来验证用户身份，并对新密码进行MD5加密后保存。
   * 如果验证码无效或不匹配，将抛出HTTP异常。
   *
   * @param userId 用户ID，用于查找和更新用户信息。
   * @param passwordDto 包含新密码和验证码的数据传输对象。
   * @returns 返回一个字符串，表示密码更新成功或失败。
   * @throws 如果验证码无效或不匹配，则抛出HttpException。
   */
  async updatePassword(userId: number, passwordDto: UpdateUserPasswordDto) {
    // 从Redis中获取用户提供的邮箱对应的验证码
    const captcha = await this.redisService.get(
      `update_password_captcha_${passwordDto.email}`,
    );

    // 如果验证码不存在，则抛出异常提示验证码已失效
    if (!captcha) {
      throw new HttpException('验证码已失效', HttpStatus.BAD_REQUEST);
    }

    // 如果用户提供的验证码与存储的验证码不匹配，则抛出异常提示验证码不正确
    if (passwordDto.captcha !== captcha) {
      throw new HttpException('验证码不正确', HttpStatus.BAD_REQUEST);
    }

    // 根据用户ID查找用户
    const foundUser = await this.userRepository.findOneBy({ id: userId });
    // 使用MD5加密新密码
    foundUser.password = md5(passwordDto.password);
    try {
      // 尝试保存更新后的用户信息
      await this.userRepository.save(foundUser);
      // 返回成功提示信息
      return '密码修改成功';
    } catch (e) {
      // 如果保存失败，记录错误并返回失败提示信息
      this.logger.error(e, UserService);
      return '密码修改失败';
    }
  }

  async update(userId: number, updateUserDto: UpdateUserDto) {
    const captcha = await this.redisService.get(
      `update_user_captcha_${updateUserDto.email}`,
    );

    if (!captcha) {
      throw new HttpException('验证码已失效', HttpStatus.BAD_REQUEST);
    }

    if (updateUserDto.captcha !== captcha) {
      throw new HttpException('验证码不正确', HttpStatus.BAD_REQUEST);
    }

    const foundUser = await this.userRepository.findOneBy({
      id: userId,
    });

    if (updateUserDto.nickName) {
      foundUser.nickName = updateUserDto.nickName;
    }
    if (updateUserDto.headPic) {
      foundUser.headPic = updateUserDto.headPic;
    }

    try {
      await this.userRepository.save(foundUser);
      return '用户信息修改成功';
    } catch (e) {
      this.logger.error(e, UserService);
      return '用户信息修改成功';
    }
  }

  async initData() {
    const user1 = new User();
    user1.username = 'zhangsan';
    user1.password = md5('111111');
    user1.email = 'xxx@xx.com';
    user1.isAdmin = true;
    user1.nickName = '张三';
    user1.phoneNumber = '13233323333';

    const user2 = new User();
    user2.username = 'lisi';
    user2.password = md5('222222');
    user2.email = 'yy@yy.com';
    user2.nickName = '李四';

    const role1 = new Role();
    role1.name = '管理员';

    const role2 = new Role();
    role2.name = '普通用户';

    const permission1 = new Permission();
    permission1.code = 'ccc';
    permission1.description = '访问 ccc 接口';

    const permission2 = new Permission();
    permission2.code = 'ddd';
    permission2.description = '访问 ddd 接口';

    user1.roles = [role1];
    user2.roles = [role2];

    role1.permissions = [permission1, permission2];
    role2.permissions = [permission1];

    await this.permissionRepository.save([permission1, permission2]);
    await this.roleRepository.save([role1, role2]);
    await this.userRepository.save([user1, user2]);
  }
}
