# Authorization (NestJS)

**Source:** https://docs.nestjs.com/security/authorization

**Authorization** বলতে বোঝায় সেই process, যেটা ঠিক করে দেয় একজন user কী কী করতে পারবে। যেমন, একজন administrative user post create, edit, আর delete করতে পারবে। কিন্তু একজন non-administrative user শুধু post read করার জন্য authorized থাকবে।

Authorization, authentication থেকে আলাদা এবং independent। তবে authorization এর জন্য একটা authentication mechanism দরকার হয়।

Authorization handle করার অনেক approach আর strategy আছে। কোন project এ কোন approach নেওয়া হবে সেটা নির্ভর করে সেই application এর নির্দিষ্ট requirement এর উপর। এই chapter এ এমন কয়েকটা approach দেখানো হবে, যেগুলো বিভিন্ন ধরনের requirement অনুযায়ী adapt করা যায়।

---

## 1. Basic RBAC Implementation

Role-based access control (**RBAC**) হলো একটা policy-neutral access-control mechanism, যেটা roles আর privileges এর উপর ভিত্তি করে define করা হয়। এই section এ, Nest [guards](https://docs.nestjs.com/guards) ব্যবহার করে একটা খুবই basic RBAC mechanism কীভাবে implement করা যায় সেটা দেখানো হবে।

প্রথমে, system এ থাকা role গুলো represent করার জন্য একটা `Role` enum বানাই:

```typescript
export enum Role {
  User = 'user',
  Admin = 'admin',
}
```

> **Hint:** আরো sophisticated system এ, তুমি role গুলো database এ store করতে পারো, অথবা external authentication provider থেকে pull করতে পারো।

এটা হয়ে গেলে, আমরা একটা `@Roles()` decorator বানাতে পারি। এই decorator দিয়ে specific resource access করার জন্য কোন কোন role লাগবে সেটা specify করা যায়।

```typescript
import { SetMetadata } from '@nestjs/common';
import { Role } from '../enums/role.enum.js';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
```

এখন যেহেতু আমাদের কাছে একটা custom `@Roles()` decorator আছে, এটা দিয়ে যেকোনো route handler decorate করা যায়।

```typescript
@Post()
@Roles(Role.Admin)
create(@Body() createCatDto: CreateCatDto) {
  this.catsService.create(createCatDto);
}
```

সবশেষে, আমরা একটা `RolesGuard` class বানাব, যেটা current user কে assign করা role গুলোর সাথে current route এর জন্য actually প্রয়োজনীয় role গুলো compare করবে। Route এর role(s) (custom metadata) access করার জন্য, আমরা `Reflector` helper class ব্যবহার করব, যেটা framework এর সাথেই out-of-the-box পাওয়া যায় এবং `@nestjs/core` package থেকে expose করা হয়।

```typescript
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );
    if (!requiredRoles) {
      return true;
    }
    const { user } = context.switchToHttp().getRequest();
    return requiredRoles.some((role) => user.roles?.includes(role));
  }
}
```

> **Hint:** Context-sensitive ভাবে `Reflector` কীভাবে ব্যবহার করবে, তার বিস্তারিত জানতে Execution context chapter এর [Reflection and metadata](https://docs.nestjs.com/fundamentals/execution-context#reflection-and-metadata) section দেখো।

> **⚠️ Notice:** এই example কে "**basic**" বলা হয়েছে, কারণ আমরা শুধু route handler level এ role এর presence check করছি। Real-world application এ, তোমার এমন endpoint/handler থাকতে পারে যেগুলোতে একাধিক operation জড়িত থাকে, আর প্রতিটার জন্য আলাদা set of permission লাগতে পারে। সেক্ষেত্রে, তোমাকে business-logic এর ভেতরে কোথাও role check করার একটা mechanism দিতে হবে, যেটা maintain করা কিছুটা কঠিন হয়ে যায়, কারণ permission গুলোকে specific action এর সাথে associate করার কোনো centralized জায়গা থাকবে না।

এই example এ, আমরা ধরে নিয়েছি যে `request.user` এ user instance আর allowed role গুলো (`roles` property এর ভেতরে) থাকে। তোমার app এ, সম্ভবত এই association টা তোমার custom **authentication guard** এ করবে — বিস্তারিত জানতে [authentication](https://docs.nestjs.com/security/authentication) chapter দেখো।

এই example কাজ করানোর জন্য, তোমার `User` class কে নিচের মতো দেখতে হবে:

```typescript
class User {
  // ...other properties
  roles: Role[];
}
```

সবশেষে, `RolesGuard` কে register করতে ভুলো না — যেমন, controller level এ, বা globally:

```typescript
providers: [
  {
    provide: APP_GUARD,
    useClass: RolesGuard,
  },
],
```

Insufficient privilege থাকা কোনো user যখন একটা endpoint request করে, তখন Nest automatically নিচের response টা return করে:

```typescript
{
  "statusCode": 403,
  "message": "Forbidden resource",
  "error": "Forbidden"
}
```

> **Hint:** যদি একটা ভিন্ন error response return করতে চাও, তাহলে boolean value return করার বদলে নিজের specific exception throw করা উচিত।

---

## 2. Claims-based Authorization

কোনো identity তৈরি হওয়ার সময়, একটা trusted party থেকে issue করা এক বা একাধিক claim সেটাকে assign করা হতে পারে। একটা claim হলো একটা name-value pair, যেটা represent করে subject কী করতে পারে — subject আসলে কী, সেটা নয়।

Nest এ Claims-based authorization implement করার জন্য, আমরা [RBAC](#1-basic-rbac-implementation) section এ যেভাবে দেখিয়েছি ঠিক একই step follow করতে পারো, একটা গুরুত্বপূর্ণ পার্থক্য সহ: specific role check করার বদলে, তোমার **permission** compare করা উচিত। প্রতিটা user এর একটা set of permission assign করা থাকবে। একইভাবে, প্রতিটা resource/endpoint define করবে সেটা access করতে কী কী permission লাগবে (যেমন, একটা dedicated `@RequirePermissions()` decorator এর মাধ্যমে)।

```typescript
@Post()
@RequirePermissions(Permission.CREATE_CAT)
create(@Body() createCatDto: CreateCatDto) {
  this.catsService.create(createCatDto);
}
```

> **Hint:** উপরের example এ, `Permission` (RBAC section এ দেখানো `Role` এর মতো) হলো একটা TypeScript enum, যেটাতে তোমার system এ থাকা সব permission আছে।

---

## 3. CASL Integrate করা

[CASL](https://casl.js.org/) হলো একটা isomorphic authorization library, যেটা ঠিক করে দেয় একজন নির্দিষ্ট client কোন কোন resource access করতে পারবে। এটা এমনভাবে design করা যাতে ধীরে ধীরে adopt করা যায়, এবং সহজেই simple claim-based থেকে শুরু করে fully-featured subject আর attribute-based authorization পর্যন্ত scale করা যায়।

শুরুতে, `@casl/ability` package install করো:

```bash
npm i @casl/ability
```

> **Hint:** এই example এ আমরা CASL বেছে নিয়েছি, কিন্তু চাইলে `accesscontrol` বা `acl` এর মতো অন্য যেকোনো library ব্যবহার করতে পারো — তোমার পছন্দ আর project এর প্রয়োজন অনুযায়ী।

Installation শেষ হলে, CASL এর mechanics illustrate করার জন্য আমরা দুটো entity class define করব: `User` আর `Article`।

```typescript
class User {
  id: number;
  isAdmin: boolean;
}
```

`User` class এ দুটো property আছে — `id`, যেটা একটা unique user identifier, আর `isAdmin`, যেটা বলে দেয় user এর administrator privilege আছে কিনা।

```typescript
class Article {
  id: number;
  isPublished: boolean;
  authorId: number;
}
```

`Article` class এ তিনটা property আছে — `id`, `isPublished`, আর `authorId`। `id` একটা unique article identifier, `isPublished` বলে দেয় article টা আগে থেকে publish করা কিনা, আর `authorId` হলো সেই user এর ID যে article টা লিখেছে।

এবার চলো এই example এর জন্য আমাদের requirement টা review আর refine করি:

- Admin রা সব entity manage (create/read/update/delete) করতে পারবে।
- User দের সব জায়গায় শুধু read-only access থাকবে।
- User রা তাদের নিজের article update করতে পারবে (`article.authorId === userId`)।
- ইতিমধ্যে publish হয়ে যাওয়া article remove করা যাবে না (`article.isPublished === true`)।

এটা মাথায় রেখে, আমরা একটা `Action` enum বানিয়ে শুরু করতে পারি, যেটা user রা entity এর সাথে যেসব সম্ভাব্য action perform করতে পারে সেগুলো represent করে:

```typescript
export enum Action {
  Manage = 'manage',
  Create = 'create',
  Read = 'read',
  Update = 'update',
  Delete = 'delete',
}
```

> **⚠️ Notice:** `manage` হলো CASL এর একটা special keyword, যেটা "any action" represent করে।

CASL library কে encapsulate করার জন্য, এখন `CaslModule` আর `CaslAbilityFactory` generate করি।

```bash
nest g module casl
nest g class casl/casl-ability.factory
```

এটা হয়ে গেলে, আমরা `CaslAbilityFactory` তে `createForUser()` method define করতে পারি। এই method একটা নির্দিষ্ট user এর জন্য `Ability` object তৈরি করবে:

```typescript
type Subjects = InferSubjects<typeof Article | typeof User> | 'all';

export type AppAbility = MongoAbility<[Action, Subjects]>;

@Injectable()
export class CaslAbilityFactory {
  createForUser(user: User) {
    const { can, cannot, build } = new AbilityBuilder(createMongoAbility);

    if (user.isAdmin) {
      can(Action.Manage, 'all'); // সবকিছুতে read-write access
    } else {
      can(Action.Read, 'all'); // সবকিছুতে শুধু read-only access
    }

    can(Action.Update, Article, { authorId: user.id });
    cannot(Action.Delete, Article, { isPublished: true });

    return build({
      // বিস্তারিত জানতে দেখো: https://casl.js.org/v6/en/guide/subject-type-detection#use-classes-as-subject-types
      detectSubjectType: (item) =>
        item.constructor as ExtractSubjectType<Subjects>,
    });
  }
}
```

> **⚠️ Notice:** `all` হলো CASL এর একটা special keyword, যেটা "any subject" represent করে।

> **Hint:** CASL v6 থেকে, `MongoAbility` হলো default ability class, যেটা পুরনো `Ability` class এর জায়গা নিয়েছে — condition-based permission কে MongoDB-এর মতো syntax দিয়ে ভালোভাবে support করার জন্য। নাম দেখে মনে হলেও, এটা MongoDB এর সাথে সরাসরি জড়িত না — এটা যেকোনো ধরনের data নিয়ে কাজ করে, শুধু object গুলোকে Mongo-এর মতো syntax এ লেখা condition এর সাথে compare করে।

> **Hint:** `MongoAbility`, `AbilityBuilder`, `AbilityClass`, আর `ExtractSubjectType` — এই class গুলো `@casl/ability` package থেকে export হয়।

> **Hint:** `detectSubjectType` option দিয়ে CASL বুঝতে পারে কীভাবে একটা object থেকে subject type বের করতে হয়। বিস্তারিত জানতে [CASL documentation](https://casl.js.org/v6/en/guide/subject-type-detection#use-classes-as-subject-types) দেখো।

উপরের example এ, আমরা `AbilityBuilder` class ব্যবহার করে `MongoAbility` instance তৈরি করেছি। যেমনটা তুমি হয়তো আন্দাজ করেছো, `can` আর `cannot` একই ধরনের argument নেয় কিন্তু এদের অর্থ ভিন্ন — `can` তোমাকে নির্দিষ্ট subject এ একটা action perform করার permission দেয়, আর `cannot` সেটা নিষেধ করে। দুটোই সর্বোচ্চ ৪টা argument নিতে পারে। এই function গুলো সম্পর্কে আরো জানতে official [CASL documentation](https://casl.js.org/v6/en/guide/intro) দেখো।

সবশেষে, `CaslModule` module definition এর `providers` আর `exports` array এ `CaslAbilityFactory` add করতে ভুলো না:

```typescript
import { Module } from '@nestjs/common';
import { CaslAbilityFactory } from './casl-ability.factory.js';

@Module({
  providers: [CaslAbilityFactory],
  exports: [CaslAbilityFactory],
})
export class CaslModule {}
```

এটা হয়ে গেলে, `CaslModule` host context এ import করা থাকলে standard constructor injection দিয়ে যেকোনো class এ `CaslAbilityFactory` inject করা যায়:

```typescript
constructor(private caslAbilityFactory: CaslAbilityFactory) {}
```

এবার এটা একটা class এ এভাবে ব্যবহার করো:

```typescript
const ability = this.caslAbilityFactory.createForUser(user);
if (ability.can(Action.Read, 'all')) {
  // "user" এর সবকিছুতে read access আছে
}
```

> **Hint:** `MongoAbility` class সম্পর্কে আরো জানতে official [CASL documentation](https://casl.js.org/v6/en/guide/intro) দেখো।

উদাহরণ হিসেবে, ধরো আমাদের কাছে একজন user আছে যে admin না। এক্ষেত্রে, user টা article read করতে পারবে, কিন্তু নতুন article create করা বা existing article remove করা তার জন্য নিষিদ্ধ হওয়া উচিত।

```typescript
const user = new User();
user.isAdmin = false;

const ability = this.caslAbilityFactory.createForUser(user);
ability.can(Action.Read, Article); // true
ability.can(Action.Delete, Article); // false
ability.can(Action.Create, Article); // false
```

> **Hint:** যদিও `MongoAbility` আর `AbilityBuilder` — দুটো class ই `can` আর `cannot` method দেয়, এদের purpose ভিন্ন এবং এরা কিছুটা ভিন্ন argument নেয়।

আরও, আমরা আমাদের requirement এ specify করেছিলাম যে user তার নিজের article update করতে পারবে:

```typescript
const user = new User();
user.id = 1;

const article = new Article();
article.authorId = user.id;

const ability = this.caslAbilityFactory.createForUser(user);
ability.can(Action.Update, article); // true

article.authorId = 2;
ability.can(Action.Update, article); // false
```

যেমনটা দেখতে পাচ্ছো, `MongoAbility` instance দিয়ে বেশ readable ভাবে permission check করা যায়। একইভাবে, `AbilityBuilder` দিয়ে একইরকম style এ permission define করা যায় (এবং বিভিন্ন condition specify করা যায়)। আরো example এর জন্য official documentation দেখো।

---

## 4. Advanced: `PoliciesGuard` Implement করা

এই section এ, আমরা দেখাব কীভাবে একটু বেশি sophisticated একটা guard বানানো যায়, যেটা check করে একজন user method-level এ configure করা specific **authorization policy** গুলো meet করছে কিনা (চাইলে class-level এ configure করা policy respect করার জন্যও এটা extend করা যায়)। এই example এ, শুধু illustration এর জন্য CASL package ব্যবহার করা হয়েছে, কিন্তু এই library ব্যবহার করা বাধ্যতামূলক না। এছাড়া, আমরা আগের section এ বানানো `CaslAbilityFactory` provider ব্যবহার করব।

প্রথমে, requirement টা একটু বিস্তারিত করি। লক্ষ্য হলো এমন একটা mechanism দেওয়া, যেটা দিয়ে প্রতি route handler এ policy check specify করা যায়। আমরা object আর function — দুটোই support করব (simple check এবং যারা functional-style code পছন্দ করে তাদের জন্য)।

চলো policy handler এর জন্য interface define করে শুরু করি:

```typescript
import { AppAbility } from '../casl/casl-ability.factory.js';

interface IPolicyHandler {
  handle(ability: AppAbility): boolean;
}

type PolicyHandlerCallback = (ability: AppAbility) => boolean;

export type PolicyHandler = IPolicyHandler | PolicyHandlerCallback;
```

উপরে যেমন বলা হয়েছে, policy handler define করার দুটো সম্ভাব্য উপায় দিয়েছি — একটা object (যে class `IPolicyHandler` interface implement করে, তার instance) আর একটা function (যেটা `PolicyHandlerCallback` type এর সাথে মেলে)।

এটা হয়ে গেলে, আমরা একটা `@CheckPolicies()` decorator বানাতে পারি। এই decorator দিয়ে specify করা যায় specific resource access করার জন্য কোন policy গুলো meet করতে হবে।

```typescript
export const CHECK_POLICIES_KEY = 'check_policy';
export const CheckPolicies = (...handlers: PolicyHandler[]) =>
  SetMetadata(CHECK_POLICIES_KEY, handlers);
```

এবার একটা `PoliciesGuard` বানাই, যেটা একটা route handler এ bind করা সব policy handler বের করে run করবে।

```typescript
@Injectable()
export class PoliciesGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private caslAbilityFactory: CaslAbilityFactory,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const policyHandlers =
      this.reflector.get<PolicyHandler[]>(
        CHECK_POLICIES_KEY,
        context.getHandler(),
      ) || [];

    const { user } = context.switchToHttp().getRequest();
    const ability = this.caslAbilityFactory.createForUser(user);

    return policyHandlers.every((handler) =>
      this.execPolicyHandler(handler, ability),
    );
  }

  private execPolicyHandler(handler: PolicyHandler, ability: AppAbility) {
    if (typeof handler === 'function') {
      return handler(ability);
    }
    return handler.handle(ability);
  }
}
```

> **Hint:** এই example এ, আমরা ধরে নিয়েছি `request.user` এ user instance আছে। তোমার app এ, সম্ভবত এই association টা তোমার custom **authentication guard** এ করবে — বিস্তারিত জানতে [authentication](https://docs.nestjs.com/security/authentication) chapter দেখো।

চলো এই example টা ভেঙে বুঝি। `policyHandlers` হলো `@CheckPolicies()` decorator দিয়ে method এ assign করা handler গুলোর একটা array। এরপর, আমরা `CaslAbilityFactory#create` method ব্যবহার করি, যেটা `Ability` object তৈরি করে, যার মাধ্যমে আমরা verify করতে পারি user এর নির্দিষ্ট action করার জন্য যথেষ্ট permission আছে কিনা। এই object টা আমরা policy handler এ পাস করি, যেটা হয় একটা function, নয়তো `IPolicyHandler` implement করা কোনো class এর instance — যেটা একটা `handle()` method expose করে, আর সেটা একটা boolean return করে। সবশেষে, আমরা `Array#every` method ব্যবহার করি এটা নিশ্চিত করার জন্য যে প্রতিটা handler `true` value return করেছে।

সবশেষে, এই guard টা test করার জন্য, যেকোনো route handler এ এটা bind করো, এবং একটা inline policy handler register করো (functional approach), এভাবে:

```typescript
@Get()
@UseGuards(PoliciesGuard)
@CheckPolicies((ability: AppAbility) => ability.can(Action.Read, Article))
findAll() {
  return this.articlesService.findAll();
}
```

বিকল্পভাবে, আমরা `IPolicyHandler` interface implement করে একটা class define করতে পারি:

```typescript
export class ReadArticlePolicyHandler implements IPolicyHandler {
  handle(ability: AppAbility) {
    return ability.can(Action.Read, Article);
  }
}
```

আর এটা এভাবে ব্যবহার করো:

```typescript
@Get()
@UseGuards(PoliciesGuard)
@CheckPolicies(new ReadArticlePolicyHandler())
findAll() {
  return this.articlesService.findAll();
}
```

> **⚠️ Notice:** যেহেতু `new` keyword দিয়ে policy handler কে in-place instantiate করতে হচ্ছে, `ReadArticlePolicyHandler` class টা Dependency Injection ব্যবহার করতে পারবে না। এটা `ModuleRef#get` method দিয়ে সমাধান করা যায় ([আরো পড়ো এখানে](https://docs.nestjs.com/fundamentals/module-ref))। মূলত, `@CheckPolicies()` decorator দিয়ে function আর instance register করার বদলে, তোমাকে `Type<IPolicyHandler>` পাস করা support করতে হবে। এরপর, তোমার guard এর ভেতরে, একটা type reference ব্যবহার করে instance retrieve করতে পারবে: `moduleRef.get(YOUR_HANDLER_TYPE)`, অথবা `ModuleRef#create` method দিয়ে dynamically instantiate ও করতে পারো।
