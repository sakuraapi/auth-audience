process.on('uncaughtException', (r) => {
  // tslint:disable:no-console
  console.log('Unhandled Rejection'.red.underline);
  console.log('-'.repeat((process.stdout as any).columns).red);
  console.log('↓'.repeat((process.stdout as any).columns).zebra.red);
  console.log('-'.repeat((process.stdout as any).columns).red);
  console.log(r);
  console.log('-'.repeat((process.stdout as any).columns).red);
  console.log('↑'.repeat((process.stdout as any).columns).zebra.red);
  console.log('-'.repeat((process.stdout as any).columns).red);
  // tslint:enable:no-console

  throw r;
});

process.on('unhandledRejection', (r) => {
  // tslint:disable:no-console
  console.log('Unhandled Rejection'.red.underline);
  console.log('-'.repeat((process.stdout as any).columns).red);
  console.log('↓'.repeat((process.stdout as any).columns).zebra.red);
  console.log('-'.repeat((process.stdout as any).columns).red);
  console.log(r);
  console.log('-'.repeat((process.stdout as any).columns).red);
  console.log('↑'.repeat((process.stdout as any).columns).zebra.red);
  console.log('-'.repeat((process.stdout as any).columns).red);
  // tslint:enable:no-console

  throw r;
});
