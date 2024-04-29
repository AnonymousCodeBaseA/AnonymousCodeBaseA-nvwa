

# Nüwa: A Network Traffic Side-channel Feature ImputationFramework Based on Pre-training

Authors:   
## Contents
- [Introduction](#Introduction)
- [Setup](#Setup)
- [Dataset and feature extraction](#Dataset-and-feature-extraction)
- [Nüwa Framework](#Nüwa Framework)
  - [Sequence2Embedding](#Sequence2Embedding)
  - [TFM](#TFM)
  - [TFI](#TFI)

- [Query and training](#Query-and-training) 
- [Acknowledgement](#Acknowledgement) 

## Introduction  
Our project is a this paper introduces a pre-training-based augmentation framework, denoted as Nüwa, which imputes the side-channel features of encrypted network traffic..  
__Modules of Nüwa framework include:__

* __Sequence2Embedding Traffic Representation__.
This module is a word-level Sequence2Embedding module, encoding time series features to token sequence for pre-training the TFI model.
* __TFM: Traffic Noise-based Self-supervised Pre-trained Masking Strategy__.
  This module is a pre-training strategy, which used to MLM task.
* __TFI: a Traffic Side-Channel Feature Imputation Module.__
  TFI is the model used to impute the missing side-channel features in the input sequences.

Background Fig.

## Setup
Before using this project, you should configure the following environment.  
1. Requirements
```
python >= 3.8
transformer = 4.30.2
pytorch = 1.12.0
torchvision==0.13.0
torchaudio==0.12.0

# OS
Ubuntu 20.04
```
2. Basic Dependencies
```
scikit-learn
flowcontainer
tokenizers
tqdm
```
3. Others  
For other packets used in the experiment, please refer to _impot.txt_
## Dataset and preparation
You can run this module in _Data pre-processing.ipynb_. Details are shown below:   

1.Dataset  
We use the open source [CIC-AndMal-2017](https://www.unb.ca/cic/datasets/andmal2017.html "CIC-AndMal-2017")  dataset, [CIRA-CICDoHBrw-2020](https://www.unb.ca/cic/datasets/dohbrw-2020.html "CIRA-CICDoHBrw-2020") dataset, [CIC-IoT-2023](https://www.unb.ca/cic/datasets/iotdataset-2023.html "CIC-IoT-2023")  IoT devices dataset, and [USTC-TFC](https://github.com/yungshenglu/USTC-TK2016 "USTC-TFC")  PC terminals dataset.

2.pcap to time series features
firstly, you need to use split TCP pcaps into flow sessions. Then, using flowcontainer tool to extract time series features with max packet length =1600 and min length of original sequence feature

## Nüwa Framework
Use 



Framework



### Sequence2Embedding  



### TFM





```python
import torch

class DataCollatorForLanguageModeling(DataCollatorMixin):    
    def torch_mask_tokens(self, inputs: Any, special_tokens_mask: Optional[Any] = None) -> Tuple[Any, Any]:
    labels = inputs.clone()
    probability_matrix = torch.full(labels.shape, self.mlm_probability)
    if special_tokens_mask is None:
        special_tokens_mask = [
            self.tokenizer.get_special_tokens_mask(val, already_has_special_tokens=True) for val in labels.tolist()
        ]
        special_tokens_mask = torch.tensor(special_tokens_mask, dtype=torch.bool)
    else:
        special_tokens_mask = special_tokens_mask.bool()

    probability_matrix.masked_fill_(special_tokens_mask, value=0.0)
    masked_indices = torch.bernoulli(probability_matrix).bool()
    labels[~masked_indices] = -100

    # Modified MLM strategies
    mask_strategy = torch.bernoulli(torch.full(labels.shape, 0.50)).bool() & masked_indices
    delete_strategy = torch.bernoulli(torch.full(labels.shape, 0.10)).bool() & masked_indices & ~mask_strategy
    infill_strategy = torch.bernoulli(torch.full(labels.shape, 0.20)).bool() & masked_indices & ~mask_strategy & ~delete_strategy
    permute_strategy = torch.bernoulli(torch.full(labels.shape, 0.10)).bool() & masked_indices & ~mask_strategy & ~delete_strategy & ~infill_strategy
    
    # Token Masking
    inputs[mask_strategy] = self.tokenizer.convert_tokens_to_ids(self.tokenizer.mask_token)

    # Token Deletion
    inputs[delete_strategy] = self.tokenizer.convert_tokens_to_ids(self.tokenizer.pad_token)

    # Text Infilling
    poisson_lengths = torch.poisson(torch.full(labels.shape, 3.0))
    infill_indices = infill_strategy.nonzero(as_tuple=True)[0]
    for idx in infill_indices:
        span_length = poisson_lengths[idx].item() if poisson_lengths[idx].numel() == 1 else 0
        if span_length > 0:
            inputs[idx:idx+span_length] = self.tokenizer.convert_tokens_to_ids(self.tokenizer.mask_token)

    # Sentence Permutation
    permute_indices = permute_strategy.nonzero(as_tuple=True)[0]
    for idx in permute_indices:
        np.random.shuffle(inputs[idx])
        
    # Keep 10% Unchanged
    unchanged_strategy = ~masked_indices

    # print("TFM strategy!")
```

### TFI

According to 

```python
Model_config = Config(
    vocab_size = 3106, # vocab size
    max_position_embeddings = 514,
    num_attention_heads = 12,
    num_hidden_layers = 6,
    type_vocab_size = 0
)
```





## Acknowledgement
Thanks for these awesome resources that were used during the development of the Nüwa：  
* https://www.unb.ca/cic/datasets/index.html
* https://huggingface.co/
* https://github.com/yungshenglu/USTC-TK2016
* https://timeseriesai.github.io/tsai/
* 
