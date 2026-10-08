# Safe Python Script - Linear Search Implementation

def linear_search(arr, target):
    """
    Searches for a target element in an array line-by-line.
    Returns index if found, else -1.
    """
    for index, element in enumerate(arr):
        if element == target:
            return index
    return -1


if __name__ == "__main__":
    numbers = [10, 25, 30, 45, 50, 75]
    search_for = 45

    result = linear_search(numbers, search_for)

    if result != -1:
        print(f"Element {search_for} found at index {result}.")
    else:
        print(f"Element {search_for} not found.")