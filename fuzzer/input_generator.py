import random

class InputGenerator:
    @staticmethod
    def generate_random_input(characters, buffer_size):
        return ''.join(random.choice(characters) for _ in range(buffer_size))

    @staticmethod
    def mutate_input(base_input, characters, mutation_rate=0.1):
        input_list = list(base_input)
        for i in range(len(input_list)):
            if random.random() < mutation_rate:
                input_list[i] = random.choice(characters)
        return ''.join(input_list)
