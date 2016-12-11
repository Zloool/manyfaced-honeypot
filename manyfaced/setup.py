from distutils.core import setup

setup(
        name='manyfaced',
        version='0.5.0',
        packages=['', 'db', 'client', 'common', 'server'],
        package_dir={'': 'manyfaced'},
        url='https://github.com/Zloool/manyfaced-honeypot',
        license='MIT License',
        author='Zhavoronkov Pavlo',
        author_email='zhavoronkov.p@gmail.com',
        description='Socket-based python web(and more) honeypot. '
)
