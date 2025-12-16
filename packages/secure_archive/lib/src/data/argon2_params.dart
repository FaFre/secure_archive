class Argon2Params {
  final int parallelism;
  final int memory;
  final int iterations;

  const Argon2Params({
    required this.parallelism,
    required this.memory,
    required this.iterations,
  });

  ///https://en.wikipedia.org/wiki/Argon2#Recommended_minimum_parameters
  factory Argon2Params.recommended() {
    return const Argon2Params(
      parallelism: 1,
      memory: 2000000, // 2 000 000 x 1kB block = 2 GB
      iterations: 1,
    );
  }

  ///https://en.wikipedia.org/wiki/Argon2#Recommended_minimum_parameters
  factory Argon2Params.memoryConstrained() {
    return const Argon2Params(
      parallelism: 1,
      memory: 64000, // 64 000 x 1kB block = 64 MB
      iterations: 3,
    );
  }
}
