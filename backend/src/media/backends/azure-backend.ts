/*
 * SPDX-FileCopyrightText: 2024 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import {
  BlobSASPermissions,
  BlobServiceClient,
  BlockBlobClient,
  ContainerClient,
  generateBlobSASQueryParameters,
  StorageSharedKeyCredential,
} from '@azure/storage-blob';
import { Inject, Injectable } from '@nestjs/common';
import { FileTypeResult } from 'file-type';

import mediaConfiguration, { MediaConfig } from '../../config/media.config';
import { MediaBackendError } from '../../errors/errors';
import { ConsoleLoggerService } from '../../logger/console-logger.service';
import { MediaBackend } from '../media-backend.interface';
import { BackendType } from './backend-type.enum';

@Injectable()
export class AzureBackend implements MediaBackend {
  private config: MediaConfig['backend']['azure'];
  private client: ContainerClient;
  private readonly credential: StorageSharedKeyCredential;

  constructor(
    private readonly logger: ConsoleLoggerService,
    @Inject(mediaConfiguration.KEY)
    private mediaConfig: MediaConfig,
  ) {
    this.logger.setContext(AzureBackend.name);
    this.config = this.mediaConfig.backend.azure;
    if (this.mediaConfig.backend.use === BackendType.AZURE) {
      // only create the client if the backend is configured to azure
      const blobServiceClient = BlobServiceClient.fromConnectionString(
        this.config.connectionString,
      );
      this.credential =
        blobServiceClient.credential as StorageSharedKeyCredential;
      this.client = blobServiceClient.getContainerClient(this.config.container);
    }
  }

  async saveFile(
    uuid: string,
    buffer: Buffer,
    fileType: FileTypeResult,
  ): Promise<null> {
    const blockBlobClient: BlockBlobClient =
      this.client.getBlockBlobClient(uuid);
    try {
      await blockBlobClient.upload(buffer, buffer.length, {
        metadata: {
          // eslint-disable-next-line @typescript-eslint/naming-convention
          'Content-Type': fileType.mime,
        },
      });
      this.logger.log(`Uploaded file ${uuid} to Azure`, 'saveFile');
      return null;
    } catch (e) {
      this.logger.error(
        `error: ${(e as Error).message}`,
        (e as Error).stack,
        'saveFile',
      );
      throw new MediaBackendError(`Could not save file '${uuid}' on Azure`);
    }
  }

  async deleteFile(uuid: string, _: unknown): Promise<void> {
    const blockBlobClient: BlockBlobClient =
      this.client.getBlockBlobClient(uuid);
    try {
      const response = await blockBlobClient.delete();
      if (response.errorCode !== undefined) {
        throw new MediaBackendError(
          `Could not delete '${uuid}' on Azure: ${response.errorCode}`,
        );
      }
      this.logger.log(`Deleted file ${uuid} on Azure`, 'deleteFile');
    } catch (e) {
      this.logger.error(
        `error: ${(e as Error).message}`,
        (e as Error).stack,
        'deleteFile',
      );
      throw new MediaBackendError(`Could not delete file ${uuid} on Azure`);
    }
  }

  getFileUrl(uuid: string, _: unknown): Promise<string> {
    const blockBlobClient: BlockBlobClient =
      this.client.getBlockBlobClient(uuid);
    const blobSAS = generateBlobSASQueryParameters(
      {
        containerName: this.config.container,
        blobName: uuid,
        permissions: BlobSASPermissions.parse('r'),
      },
      this.credential,
    );
    return Promise.resolve(`${blockBlobClient.url}?${blobSAS.toString()}`);
  }
}
