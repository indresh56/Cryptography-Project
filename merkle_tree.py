import hashlib
import math

class MerkleTree:
    def __init__(self, file_path, chunk_size=4096):
        self.file_path = file_path
        self.chunk_size = chunk_size
        self.leaves = self._get_file_chunks()
        self.tree = self._build_merkle_tree(self.leaves)
    
    def _hash(self, data):
        if isinstance(data, str):
            data = data.encode()
        return hashlib.sha256(data).hexdigest()
    
    def _get_file_chunks(self):
        hashes = []
        try:
            with open(self.file_path, "rb") as f:
                while chunk := f.read(self.chunk_size):
                    hashes.append(self._hash(chunk))
            
            # Ensure we have at least one leaf node
            if not hashes:
                hashes.append(self._hash(b""))
                
            return hashes
        except Exception as e:
            print(f"Error reading file chunks: {e}")
            return [self._hash(b"ERROR")]
    
    def _build_merkle_tree(self, leaves):
        if not leaves:
            return [[self._hash(b"")]]
        
        # Start with leaf nodes as the first level
        tree = [leaves]
        
        # Build tree bottom-up until we reach the root
        while len(tree[-1]) > 1:
            level = []
            prev_level = tree[-1]
            
            # Combine pairs of nodes
            for i in range(0, len(prev_level), 2):
                left = prev_level[i]
                # If odd number of nodes, duplicate the last one
                right = prev_level[i + 1] if i + 1 < len(prev_level) else left
                combined_hash = self._hash(left + right)
                level.append(combined_hash)
            
            tree.append(level)
        
        return tree
    
    def get_root(self):
        return self.tree[-1][0] if self.tree and self.tree[-1] else None
    
    def print_tree(self):
        for i, level in enumerate(self.tree):
            print(f"Level {i}: {level}")
    
    def verify_integrity(self, expected_root):
        calculated_root = self.get_root()
        return calculated_root == expected_root
    
    def get_proof(self, leaf_index):
        if not self.tree or leaf_index >= len(self.tree[0]):
            return []
        
        proof = []
        idx = leaf_index
        
        for level in range(len(self.tree) - 1):
            is_right = idx % 2 == 0
            if is_right and idx + 1 < len(self.tree[level]):
                proof.append(('right', self.tree[level][idx + 1]))
            elif not is_right:
                proof.append(('left', self.tree[level][idx - 1]))
            
            idx //= 2
        
        return proof
    
    def verify_proof(self, leaf_hash, proof, root_hash):
        current = leaf_hash
        
        for direction, hash_value in proof:
            if direction == 'left':
                current = self._hash(hash_value + current)
            else:
                current = self._hash(current + hash_value)
        
        return current == root_hash
    
def merkle_tree_to_ascii_recurse(tree, level=0, index=0, prefix=""):
    if not tree or not tree[-1]:
        return "Empty tree"
    
    # Shortened hash representation for display
    def short_hash(h):
        return h[:6] + "..." + h[-6:] if h else "None"
    
    if level >= len(tree) or index >= len(tree[level]):
        return ""
    
    node_str = short_hash(tree[level][index])
    
    left_child_idx = index * 2
    right_child_idx = index * 2 + 1
    
    left_branch = (
        merkle_tree_to_ascii_recurse(tree, level - 1, left_child_idx, prefix + "    ")
        if level > 0 and left_child_idx < len(tree[level - 1])
        else ""
    )
    
    right_branch = (
        merkle_tree_to_ascii_recurse(tree, level - 1, right_child_idx, prefix + "    ")
        if level > 0 and right_child_idx < len(tree[level - 1])
        else ""
    )
    
    result = prefix + node_str + "\n"
    
    if left_branch or right_branch:
        result += prefix + "├── " + left_branch if left_branch else ""
        result += prefix + "└── " + right_branch if right_branch else ""
    
    return result

def merkle_tree_to_ascii(tree):
    if not tree:
        return "Empty tree"
    return merkle_tree_to_ascii_recurse(tree, len(tree) - 1, 0)

import networkx as nx
import matplotlib.pyplot as plt
def merkle_tree_visualize(tree,filename = "tree"):
    if not tree:
        print("Empty tree, nothing to visualize.")
        return
    
    G = nx.DiGraph()
    pos = {}
    node_labels = {}
    y_offset = 0
    max_width = max(len(level) for level in tree)  
    
    for level_idx, level in enumerate(tree):
        x_offset = 0
        spacing = max_width / (len(level) + 1)  

        for node_idx, node_hash in enumerate(level):
            node_name = f"{level_idx}-{node_idx}"
            G.add_node(node_name)
            pos[node_name] = (x_offset, -level_idx) 
            node_labels[node_name] = node_hash[:6]  # Display only first 6 chars for readability
            x_offset += spacing
    
    for level_idx in range(len(tree) - 1):
        for node_idx in range(len(tree[level_idx])):
            parent_idx = node_idx // 2
            parent_name = f"{level_idx + 1}-{parent_idx}"
            child_name = f"{level_idx}-{node_idx}"
            G.add_edge(parent_name, child_name)
    
    plt.figure(figsize=(12, 8))  # Increased figure size
    nx.draw(G, pos, with_labels=True, labels=node_labels, node_color='lightblue', node_size=1000, edge_color='gray', font_size=8)
    plt.title("Merkle Tree Visualization")
    plt.savefig(f"{filename}.png", dpi=300)
    #plt.show()
    print("Merkle tree visualization saved as 'tree.png'.")

# For testing
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        print(f"Generating Merkle Tree for: {file_path}")
        
        try:
            merkle_tree = MerkleTree(file_path)
            
            print("\nMerkle Tree Structure:")
            merkle_tree.print_tree()
            
            print(f"\nMerkle Root: {merkle_tree.get_root()}")
            
            merkle_tree_visualize(merkle_tree.tree)

            print("\nASCII Representation:")
            print(merkle_tree_to_ascii(merkle_tree.tree))
            
        except Exception as e:
            print(f"Error: {e}")
    else:
        print("Usage: python merkle_tree.py <file_path>")